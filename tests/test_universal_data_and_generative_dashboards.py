"""End-to-end tests for universal data ingestion, DuckDB 2.0 sandbox, PDF/OCR parsing, extract_web_data, and self-hosted ECharts Generative UI."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch
from xml.sax.saxutils import escape as xml_escape

from cryptography.fernet import Fernet
from docx import Document as DocxDocument
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from argo_core.analytics import engine as analytics_engine  # noqa: E402
from argo_core.analytics.engine import (  # noqa: E402
    execute_duckdb_query,
    is_duckdb_runtime_supported,
    verify_analytics_runtime,
)
from argo_core.config import ArgoSettings  # noqa: E402
from argo_core.connectors.google_oauth import DefaultGoogleOAuthTransport  # noqa: E402
from argo_core.llm.router import LLMRequest  # noqa: E402
from argo_core.main import create_app  # noqa: E402
from argo_core.security.ssrf import (  # noqa: E402
    PublicFetchError,
    PublicHttpResponse,
    SSRFBlockedError,
)
from argo_core.tools.public_web import extract_web_data, fetch_public_webpage  # noqa: E402
from argo_core.watchdog.resource_guard import HostResourceGuard  # noqa: E402


class _FakeHttpResponse:
    """Minimal context-manager HTTP response double for DefaultGoogleOAuthTransport."""

    def __init__(self, body: bytes | str) -> None:
        self._bytes = body.encode("utf-8") if isinstance(body, str) else body

    def read(self, n: int = -1) -> bytes:
        return self._bytes if n is None or n < 0 else self._bytes[:n]

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        del exc_type, exc, tb
        return False


class _StubPublicHttpFetcher:
    """Deterministic PublicHttpFetcher double returning scripted PublicHttpResponse payloads."""

    def __init__(self, responses: dict[str, PublicHttpResponse]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    async def fetch(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int = 2_097_152,
    ) -> PublicHttpResponse:
        del headers, max_bytes
        self.calls.append(url)
        if url not in self._responses:
            raise PublicFetchError(f"Unexpected URL in stub fetcher: {url}")
        return self._responses[url]


def _col_letter(idx: int) -> str:
    """Convert 1-based column index to Excel column letters (1 -> A)."""
    out = ""
    n = idx
    while n > 0:
        n, rem = divmod(n - 1, 26)
        out = chr(65 + rem) + out
    return out


def _build_test_xlsx_bytes(sheets: dict[str, list[list[Any]]]) -> bytes:
    """Build a valid multi-sheet OOXML .xlsx archive in memory using stdlib zipfile."""
    sheet_items = list(sheets.items())
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        overrides = [
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        ]
        wb_sheets = []
        wb_rels = []
        for idx, (sheet_name, rows) in enumerate(sheet_items, start=1):
            overrides.append(
                f'<Override PartName="/xl/worksheets/sheet{idx}.xml" '
                'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            )
            wb_sheets.append(
                f'<sheet name="{xml_escape(sheet_name)}" sheetId="{idx}" r:id="rId{idx}"/>'
            )
            wb_rels.append(
                f'<Relationship Id="rId{idx}" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                f'Target="worksheets/sheet{idx}.xml"/>'
            )

            row_xml_parts: list[str] = []
            for r_idx, row in enumerate(rows, start=1):
                cell_parts: list[str] = []
                for c_idx, val in enumerate(row, start=1):
                    ref = f"{_col_letter(c_idx)}{r_idx}"
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        cell_parts.append(f'<c r="{ref}"><v>{val}</v></c>')
                    else:
                        text = xml_escape("" if val is None else str(val))
                        cell_parts.append(f'<c r="{ref}" t="inlineStr"><is><t>{text}</t></is></c>')
                row_xml_parts.append(f'<row r="{r_idx}">{"".join(cell_parts)}</row>')

            sheet_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                f'<sheetData>{"".join(row_xml_parts)}</sheetData>'
                "</worksheet>"
            )
            zf.writestr(f"xl/worksheets/sheet{idx}.xml", sheet_xml)

        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            f'{"".join(overrides)}'
            "</Types>"
        )
        zf.writestr("[Content_Types].xml", content_types)

        root_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/>'
            "</Relationships>"
        )
        zf.writestr("_rels/.rels", root_rels)

        workbook_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f'<sheets>{"".join(wb_sheets)}</sheets>'
            "</workbook>"
        )
        zf.writestr("xl/workbook.xml", workbook_xml)

        workbook_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'{"".join(wb_rels)}'
            "</Relationships>"
        )
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
    return buf.getvalue()


def _build_test_docx_bytes() -> bytes:
    """Build a genuine .docx document with headings, paragraphs, and a table."""
    doc = DocxDocument()
    doc.add_heading("Operations Quarterly Brief", level=1)
    doc.add_paragraph("Cloud unit economics improved across Europe and North America.")
    tbl = doc.add_table(rows=3, cols=3)
    headers = ["Region", "Status", "Budget"]
    for idx, label in enumerate(headers):
        tbl.rows[0].cells[idx].text = label
    rows = [
        ["EMEA", "On Track", "125000"],
        ["AMER", "Expanded", "240000"],
    ]
    for r_idx, row in enumerate(rows, start=1):
        for c_idx, val in enumerate(row):
            tbl.rows[r_idx].cells[c_idx].text = val
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_multipage_vector_pdf_bytes() -> bytes:
    """Construct a valid 3-page PDF 1.4 with vector text and a drawn line-grid table on page 2."""
    xs = [60, 180, 300, 420]
    ys = [620, 650, 680, 710, 740]
    p2_lines = ["1 w"]
    for y in ys:
        p2_lines.append(f"{xs[0]} {y} m {xs[-1]} {y} l S")
    for x in xs:
        p2_lines.append(f"{x} {ys[0]} m {x} {ys[-1]} l S")

    table_rows = [
        ["Region", "Quarter", "Revenue"],
        ["North", "Q3", "180000"],
        ["South", "Q3", "120000"],
        ["West", "Q3", "95000"],
    ]
    for r_idx, row in enumerate(table_rows):
        y_text = ys[-1] - 20 - (r_idx * 30)
        for c_idx, cell in enumerate(row):
            x_text = xs[c_idx] + 10
            p2_lines.append(f"BT /F1 11 Tf {x_text} {y_text} Td ({_pdf_escape(cell)}) Tj ET")

    streams = [
        (
            "BT /F1 14 Tf 60 720 Td (Executive Financial Report Page One) Tj ET\n"
            "BT /F1 11 Tf 60 690 Td (OverviewRevenueBaseline: Total operating margin reached 24 percent.) Tj ET"
        ),
        "\n".join(p2_lines),
        (
            "BT /F1 14 Tf 60 720 Td (Outlook And Guidance Page Three) Tj ET\n"
            "BT /F1 11 Tf 60 690 Td (FY27ForecastMarker: Planned datacenter efficiency expansion continues.) Tj ET"
        ),
    ]

    # Object layout:
    # 1: Catalog, 2: Pages, 3: Helvetica Font, (4,5),(6,7),(8,9): Page + Content stream pairs
    objects: list[bytes] = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [4 0 R 6 0 R 8 0 R] /Count 3 >>\nendobj\n")
    objects.append(b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

    for idx, content in enumerate(streams):
        page_obj_num = 4 + idx * 2
        stream_obj_num = 5 + idx * 2
        page_obj = (
            f"{page_obj_num} 0 obj\n"
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            "/Resources << /Font << /F1 3 0 R >> >> "
            f"/Contents {stream_obj_num} 0 R >>\n"
            "endobj\n"
        ).encode("latin1")
        stream_bytes = content.encode("latin1")
        stream_obj = (
            f"{stream_obj_num} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin1")
            + stream_bytes
            + b"\nendstream\nendobj\n"
        )
        objects.append(page_obj)
        objects.append(stream_obj)

    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("latin1"))
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("latin1"))
    out.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode("latin1")
    )
    return bytes(out)


def _build_scanned_image_only_pdf_bytes() -> bytes:
    """Create a purely rasterized PDF with zero embedded text operators using Pillow."""
    img = Image.new("RGB", (600, 320), color=(248, 250, 252))
    draw = ImageDraw.Draw(img)
    draw.rectangle([30, 30, 570, 290], outline=(30, 41, 59), width=4)
    draw.rectangle([70, 80, 240, 240], fill=(37, 99, 235))
    draw.rectangle([290, 120, 520, 240], fill=(22, 163, 74))
    buf = io.BytesIO()
    img.save(buf, format="PDF", resolution=150.0)
    return buf.getvalue()


class TestUniversalDataAndGenerativeDashboards(unittest.TestCase):
    """Comprehensive verification for analytics ingestion, DuckDB sandbox, PDFs, web extract, and UI."""

    @staticmethod
    def _sso(email: str = "alice@example.com") -> dict[str, str]:
        return {
            "X-Auth-Request-Email": email,
            "X-Auth-Request-User": email.split("@", 1)[0],
        }

    def _build_env(self, tmp: str, *, llm_transport=None, http_fetcher=None):
        db_path = Path(tmp) / "argo.db"
        static_dir = Path(tmp) / "static"
        static_dir.mkdir(parents=True, exist_ok=True)
        (static_dir / "index.html").write_text(
            "<!doctype html><html><body><div id='root'></div></body></html>",
            encoding="utf-8",
        )
        guard = HostResourceGuard(
            metrics_provider=lambda: {
                "ram_percent": 30.0,
                "ram_total_gb": 16.0,
                "cpu_percent": 10.0,
                "disk_percent": 20.0,
            },
            alert_cooldown_seconds=0.0,
        )
        settings = ArgoSettings(
            master_key=Fernet.generate_key().decode("ascii"),
            db_path=str(db_path),
            workspace_files_root=str(Path(tmp) / "workspace_files"),
            valkey_url="valkey://127.0.0.1:6399/0",
            desktop_volumes_root=str(Path(tmp) / "desktops"),
            desktop_idle_timeout_seconds=300.0,
            public_base_url="https://argo.example.com",
            static_dir=str(static_dir),
        )
        return create_app(
            settings=settings,
            guard=guard,
            llm_transport=llm_transport,
            public_http_fetcher=http_fetcher,
        )

    def test_streamed_csv_xlsx_docx_ingestion_duckdb_sql_and_sso_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                # 1) Streamed 15,000-row CSV upload
                csv_buf = io.StringIO()
                writer = csv.writer(csv_buf)
                writer.writerow(["region", "category", "revenue", "units", "order_date"])
                regions = ("North", "South", "East")
                categories = ("Hardware", "Software")
                expected_total_rev = 0
                for idx in range(15_000):
                    reg = regions[idx % 3]
                    cat = categories[idx % 2]
                    rev = 100 + (idx % 50)
                    expected_total_rev += rev
                    writer.writerow([reg, cat, rev, (idx % 5) + 1, f"2026-0{(idx % 3) + 1}-15"])
                csv_bytes = csv_buf.getvalue().encode("utf-8")

                up_csv = client.post(
                    "/api/files",
                    headers={
                        **self._sso("alice@example.com"),
                        "Content-Type": "text/csv",
                        "X-File-Name": "sales_15k.csv",
                    },
                    content=csv_bytes,
                )
                self.assertEqual(up_csv.status_code, 201, up_csv.text)
                csv_meta = up_csv.json()
                csv_id = csv_meta["id"]
                self.assertTrue(csv_meta["derived_datasets"])

                # 2) Streamed multi-sheet .xlsx upload
                xlsx_bytes = _build_test_xlsx_bytes(
                    {
                        "Orders": [
                            ["region", "actual_sales", "quarter"],
                            ["North", 50000, "Q3"],
                            ["South", 42000, "Q3"],
                        ],
                        "Targets": [
                            ["region", "target_sales"],
                            ["North", 45000],
                            ["South", 50000],
                        ],
                    }
                )
                up_xlsx = client.post(
                    "/api/files",
                    headers={
                        **self._sso("alice@example.com"),
                        "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "X-File-Name": "quarterly.xlsx",
                    },
                    content=xlsx_bytes,
                )
                self.assertEqual(up_xlsx.status_code, 201, up_xlsx.text)
                xlsx_meta = up_xlsx.json()
                xlsx_id = xlsx_meta["id"]
                xlsx_ds_ids = {d["id"] for d in xlsx_meta["derived_datasets"]}
                self.assertIn(f"file:{xlsx_id}:sheet_orders", xlsx_ds_ids)
                self.assertIn(f"file:{xlsx_id}:sheet_targets", xlsx_ds_ids)

                # 3) Genuine .docx upload with paragraph + table
                docx_bytes = _build_test_docx_bytes()
                up_docx = client.post(
                    "/api/files",
                    headers={
                        **self._sso("alice@example.com"),
                        "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "X-File-Name": "brief.docx",
                    },
                    content=docx_bytes,
                )
                self.assertEqual(up_docx.status_code, 201, up_docx.text)
                docx_meta = up_docx.json()
                docx_id = docx_meta["id"]
                self.assertTrue(docx_meta["has_text_preview"])
                docx_ds_ids = {d["id"] for d in docx_meta["derived_datasets"]}
                self.assertIn(f"file:{docx_id}:table_1", docx_ds_ids)

                # 4) Generic .txt upload must NOT create a .derived subdirectory
                up_txt = client.post(
                    "/api/files",
                    headers={
                        **self._sso("alice@example.com"),
                        "Content-Type": "text/plain",
                        "X-File-Name": "note.txt",
                    },
                    content=b"plain note without analytical parquet",
                )
                self.assertEqual(up_txt.status_code, 201, up_txt.text)
                txt_id = up_txt.json()["id"]

                # Verify 0o444 ZSTD Parquet files on disk and no .tmp leftovers
                ws_root = Path(tmp) / "workspace_files"
                derived_csv_parquets = list(ws_root.glob(f"*/.derived/{csv_id}/*.parquet"))
                self.assertTrue(derived_csv_parquets)
                for pq in derived_csv_parquets:
                    self.assertEqual(stat.S_IMODE(pq.stat().st_mode), 0o444)
                self.assertEqual(list(ws_root.glob(f"*/.derived/{txt_id}/*")), [])
                self.assertEqual(list((ws_root / ".tmp").glob("*")), [])

                # 5) Bind datasets to a Living Page and verify GET /data + DuckDB SQL + Bob 403
                page_resp = client.post(
                    "/api/pages",
                    headers=self._sso("alice@example.com"),
                    json={
                        "title": "Sales Analytics",
                        "render_mode": "sandboxed_html",
                        "content_payload": "<html><body><h1>Sales</h1></body></html>",
                        "allowed_collections": [
                            f"file:{csv_id}",
                            f"file:{xlsx_id}:sheet_orders",
                            f"file:{xlsx_id}:sheet_targets",
                            f"file:{docx_id}:table_1",
                        ],
                    },
                )
                self.assertEqual(page_resp.status_code, 201, page_resp.text)
                page_slug = page_resp.json()["slug"]

                data_resp = client.get(
                    f"/api/pages/{page_slug}/data?limit=2000",
                    headers=self._sso("alice@example.com"),
                )
                self.assertEqual(data_resp.status_code, 200, data_resp.text)
                pdata = data_resp.json()
                self.assertIn(f"file:{csv_id}", pdata["datasets"])
                self.assertLessEqual(len(pdata["datasets"][f"file:{csv_id}"]), 2000)
                csv_prof = pdata["dataset_profiles"][f"file:{csv_id}"]
                self.assertEqual(csv_prof["row_count"], 15_000)
                self.assertTrue(csv_prof["is_sampled"])

                # DuckDB exact aggregation over 15k rows
                agg_resp = client.post(
                    f"/api/pages/{page_slug}/sql",
                    headers=self._sso("alice@example.com"),
                    json={
                        "sql": "SELECT COUNT(*) AS cnt, SUM(revenue) AS total_rev FROM t0",
                        "engine": "duckdb",
                    },
                )
                self.assertEqual(agg_resp.status_code, 200, agg_resp.text)
                agg_json = agg_resp.json()
                expected_engine = "duckdb" if is_duckdb_runtime_supported() else "sqlite"
                self.assertEqual(agg_json["engine"], expected_engine)
                self.assertEqual(agg_json["rows"][0]["cnt"], 15_000)
                self.assertEqual(agg_json["rows"][0]["total_rev"], expected_total_rev)

                # DuckDB PIVOT over 15k rows
                pivot_resp = client.post(
                    f"/api/pages/{page_slug}/sql",
                    headers=self._sso("alice@example.com"),
                    json={
                        "sql": "SELECT * FROM (PIVOT t0 ON category USING SUM(revenue) GROUP BY region) ORDER BY region",
                        "engine": "auto",
                    },
                )
                self.assertEqual(pivot_resp.status_code, 200, pivot_resp.text)
                pivot_rows = pivot_resp.json()["rows"]
                self.assertEqual(len(pivot_rows), 3)
                self.assertIn("Hardware", pivot_rows[0])
                self.assertIn("Software", pivot_rows[0])

                # Cross-sheet SQL JOIN between Orders (t1) and Targets (t2)
                join_resp = client.post(
                    f"/api/pages/{page_slug}/sql",
                    headers=self._sso("alice@example.com"),
                    json={
                        "sql": (
                            "SELECT o.region, o.actual_sales - t.target_sales AS variance "
                            "FROM t1 o JOIN t2 t ON o.region = t.region ORDER BY o.region"
                        ),
                        "engine": "auto",
                    },
                )
                self.assertEqual(join_resp.status_code, 200, join_resp.text)
                self.assertEqual(
                    join_resp.json()["rows"],
                    [
                        {"region": "North", "variance": 5000},
                        {"region": "South", "variance": -8000},
                    ],
                )

                # DOCX table query (t3)
                docx_sql = client.post(
                    f"/api/pages/{page_slug}/sql",
                    headers=self._sso("alice@example.com"),
                    json={"sql": "SELECT Region, Status FROM t3 ORDER BY Region"},
                )
                self.assertEqual(docx_sql.status_code, 200, docx_sql.text)
                self.assertEqual(len(docx_sql.json()["rows"]), 2)

                # Bob (different SSO principal) must receive HTTP 403 reading or querying Alice's file Page
                bob_data = client.get(
                    f"/api/pages/{page_slug}/data",
                    headers=self._sso("bob@example.com"),
                )
                self.assertEqual(bob_data.status_code, 403, bob_data.text)
                bob_sql = client.post(
                    f"/api/pages/{page_slug}/sql",
                    headers=self._sso("bob@example.com"),
                    json={"sql": "SELECT COUNT(*) FROM t0"},
                )
                self.assertEqual(bob_sql.status_code, 403, bob_sql.text)

                # Deleting CSV file removes its .derived/<id>/ directory
                del_resp = client.delete(
                    f"/api/files/{csv_id}",
                    headers=self._sso("alice@example.com"),
                )
                self.assertEqual(del_resp.status_code, 200, del_resp.text)
                self.assertEqual(list(ws_root.glob(f"*/.derived/{csv_id}")), [])

    def test_multipage_pdf_tables_drive_binary_excerpt_and_scanned_pdf_vision(self) -> None:
        llm_requests: list[LLMRequest] = []
        queued_actions: list[list[dict[str, Any]]] = []

        async def fake_llm(req: LLMRequest) -> dict[str, Any]:
            llm_requests.append(req)
            actions = queued_actions.pop(0) if queued_actions else []
            return {
                "text": json.dumps({"summary": "Analyzed PDF attachments.", "actions": actions}),
                "input_tokens": 30,
                "output_tokens": 18,
                "model": "google:gemini-3.8-flash",
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=fake_llm)
            with TestClient(app) as client:
                vector_pdf = _build_multipage_vector_pdf_bytes()
                up_pdf = client.post(
                    "/api/files",
                    headers={
                        **self._sso("alice@example.com"),
                        "Content-Type": "application/pdf",
                        "X-File-Name": "quarterly_report.pdf",
                    },
                    content=vector_pdf,
                )
                self.assertEqual(up_pdf.status_code, 201, up_pdf.text)
                pdf_meta = up_pdf.json()
                pdf_id = pdf_meta["id"]
                self.assertEqual(pdf_meta["page_count"], 3)
                self.assertTrue(pdf_meta["has_text_preview"])
                pdf_ds_ids = {d["id"] for d in pdf_meta["derived_datasets"]}
                self.assertIn(f"file:{pdf_id}:pages", pdf_ds_ids)
                self.assertIn(f"file:{pdf_id}:table_1", pdf_ds_ids)

                # Verify Page binding + DuckDB SQL over extracted PDF table_1
                pdf_page = client.post(
                    "/api/pages",
                    headers=self._sso("alice@example.com"),
                    json={
                        "title": "PDF Financial Table",
                        "render_mode": "sandboxed_html",
                        "content_payload": "<html><body>PDF Table</body></html>",
                        "allowed_collections": [f"file:{pdf_id}:table_1"],
                    },
                )
                self.assertEqual(pdf_page.status_code, 201, pdf_page.text)
                tbl_sql = client.post(
                    f"/api/pages/{pdf_page.json()['slug']}/sql",
                    headers=self._sso("alice@example.com"),
                    json={"sql": "SELECT Region, Revenue FROM t0 ORDER BY Region"},
                )
                self.assertEqual(tbl_sql.status_code, 200, tbl_sql.text)
                tbl_rows = tbl_sql.json()["rows"]
                self.assertEqual(len(tbl_rows), 3)
                self.assertEqual(tbl_rows[0]["Region"], "North")

                # Create analyst bot & test read_workspace_file page_start/page_end + query + vision fallback
                bot_resp = client.post(
                    "/api/bots",
                    headers=self._sso("alice@example.com"),
                    json={
                        "name": "Document Analyst",
                        "role": "Analyst",
                        "outbound_rbac": "internal",
                        "tools": ["read_workspace_file", "data_query"],
                    },
                )
                self.assertEqual(bot_resp.status_code, 201, bot_resp.text)
                bot_slug = bot_resp.json()["slug"]

                queued_actions.append(
                    [
                        {
                            "type": "read_workspace_file",
                            "file_id": pdf_id,
                            "page_start": 2,
                            "page_end": 3,
                        },
                        {
                            "type": "read_workspace_file",
                            "file_id": pdf_id,
                            "query": "FY27ForecastMarker",
                        },
                    ]
                )
                queued_actions.append([])
                msg_vec = client.post(
                    f"/api/bots/{bot_slug}/messages",
                    headers=self._sso("alice@example.com"),
                    json={
                        "text": "Read pages 2 to 3 of the quarterly PDF and find the FY27 marker.",
                        "attachment_ids": [pdf_id],
                    },
                )
                self.assertEqual(msg_vec.status_code, 200, msg_vec.text)
                action_results = msg_vec.json()["result"]["actions"]
                win_act = next(a for a in action_results if a.get("page_start") == 2)
                self.assertEqual(win_act["total_pages"], 3)
                self.assertIn("Outlook And Guidance Page Three", win_act["content"])
                self.assertNotIn("OverviewRevenueBaseline", win_act["content"])

                search_act = next(
                    a for a in action_results if "FY27ForecastMarker" in str(a.get("content") or "")
                )
                self.assertIn("[Page 3]", search_act["content"])

                # Scanned raster-only PDF attached in chat must produce PNG vision frames in LLMRequest.images
                scanned_pdf = _build_scanned_image_only_pdf_bytes()
                up_scan = client.post(
                    "/api/files",
                    headers={
                        **self._sso("alice@example.com"),
                        "Content-Type": "application/pdf",
                        "X-File-Name": "scanned_invoice.pdf",
                    },
                    content=scanned_pdf,
                )
                self.assertEqual(up_scan.status_code, 201, up_scan.text)
                scan_meta = up_scan.json()
                self.assertEqual(scan_meta["scanned_pages"], [1])

                llm_requests.clear()
                queued_actions.append([])
                msg_scan = client.post(
                    f"/api/bots/{bot_slug}/messages",
                    headers=self._sso("alice@example.com"),
                    json={
                        "text": "Inspect this scanned PDF visually.",
                        "attachment_ids": [scan_meta["id"]],
                    },
                )
                self.assertEqual(msg_scan.status_code, 200, msg_scan.text)
                self.assertTrue(llm_requests)
                self.assertTrue(llm_requests[0].images, "Expected rendered PNG vision frames for scanned PDF")
                self.assertTrue(llm_requests[0].images[0].startswith(b"\x89PNG\r\n\x1a\n"))

            # Google Drive binary PDF read_drive_file_excerpt test via patched urlopen
            transport = DefaultGoogleOAuthTransport()

            def fake_urlopen(req, timeout=20):
                del timeout
                url_str = req.full_url if hasattr(req, "full_url") else str(req)
                if "alt=media" in url_str:
                    return _FakeHttpResponse(vector_pdf)
                return _FakeHttpResponse(
                    json.dumps(
                        {
                            "id": "drv_pdf_1",
                            "name": "q3_report.pdf",
                            "mimeType": "application/pdf",
                            "modifiedTime": "2026-11-10T12:00:00Z",
                            "webViewLink": "https://drive.google.com/file/d/drv_pdf_1/view",
                        }
                    )
                )

            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                drive_res = asyncio.run(
                    transport.read_drive_file_excerpt(
                        access_token="ya29.fake",
                        file_id="drv_pdf_1",
                        mime_type="application/pdf",
                    )
                )
            self.assertEqual(drive_res["page_count"], 3)
            self.assertIn("Executive Financial Report", drive_res["excerpt"])
            self.assertEqual(len(drive_res["tables_preview"]), 1)

    def test_extract_web_data_webpage_pagination_and_ssrf_guard(self) -> None:
        table_rows_html = "".join(
            f"<tr><td>Item-{i:03d}</td><td>Cat-{i % 5}</td><td>{10 + i}.50</td></tr>"
            for i in range(250)
        )
        big_table_html = (
            "<html><head><title>Market Prices</title></head><body>"
            "<table><thead><tr><th>product</th><th>category</th><th>price</th></tr></thead>"
            f"<tbody>{table_rows_html}</tbody></table></body></html>"
        )
        json_ld_html = (
            '<html><head><script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"ItemList","itemListElement":['
            '{"@type":"ListItem","item":{"@type":"Product","name":"Alpha Switch","sku":"SW-1","offers":{"price":"199"}}},'
            '{"@type":"ListItem","item":{"@type":"Product","name":"Beta Router","sku":"RT-2","offers":{"price":"349"}}}'
            "]}</script></head><body>Catalog</body></html>"
        )
        long_prose = " ".join(f"paragraph-{i}-telemetry-signal" for i in range(1200))
        long_article_html = (
            "<html><head><title>Long Brief</title>"
            '<script type="application/ld+json">{"@type":"Article","headline":"Cloud Shift","author":{"name":"Ada"}}</script>'
            f"</head><body><article><h1>Cloud Shift</h1><p>{long_prose}</p>"
            "<table><tr><th>metric</th><th>value</th></tr><tr><td>latency</td><td>12ms</td></tr></table>"
            "</article></body></html>"
        )
        direct_csv_bytes = b"symbol,close,volume\nNVDA,142.5,12000\nMSFT,431.0,9400\n"

        stub_fetcher = _StubPublicHttpFetcher(
            {
                "https://data.example.com/prices": PublicHttpResponse(
                    url="https://data.example.com/prices",
                    status_code=200,
                    headers={"content-type": "text/html; charset=utf-8"},
                    body=big_table_html,
                ),
                "https://shop.example.com/catalog": PublicHttpResponse(
                    url="https://shop.example.com/catalog",
                    status_code=200,
                    headers={"content-type": "text/html; charset=utf-8"},
                    body=json_ld_html,
                ),
                "https://files.example.com/market.csv": PublicHttpResponse(
                    url="https://files.example.com/market.csv",
                    status_code=200,
                    headers={"content-type": "text/csv; charset=utf-8"},
                    body=direct_csv_bytes.decode("utf-8"),
                    raw_bytes=direct_csv_bytes,
                ),
                "https://news.example.com/long-article": PublicHttpResponse(
                    url="https://news.example.com/long-article",
                    status_code=200,
                    headers={"content-type": "text/html; charset=utf-8"},
                    body=long_article_html,
                ),
            }
        )

        llm_calls = 0

        async def zero_expected_llm(req: LLMRequest) -> dict[str, Any]:
            nonlocal llm_calls
            llm_calls += 1
            return {"text": "{}", "input_tokens": 0, "output_tokens": 0}

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=zero_expected_llm, http_fetcher=stub_fetcher)
            with TestClient(app) as client:
                repo = app.state.repo

                # 1) HTML table extraction -> 0o444 Parquet with 0 LLM tokens
                ext_table = asyncio.run(
                    extract_web_data(
                        "https://data.example.com/prices",
                        target_collection="scraped_prices",
                        repo=repo,
                        fetcher=stub_fetcher,
                    )
                )
                self.assertEqual(ext_table["status"], "ok")
                self.assertEqual(ext_table["extraction_kind"], "html_table")
                self.assertEqual(ext_table["row_count"], 250)
                self.assertEqual(llm_calls, 0)

                pq_path = Path(tmp) / "analytics" / "scraped_prices" / "main.parquet"
                self.assertTrue(pq_path.is_file())
                self.assertEqual(stat.S_IMODE(pq_path.stat().st_mode), 0o444)

                # Query materialized scraped collection via DuckDB page SQL
                page_resp = client.post(
                    "/api/pages",
                    headers=self._sso("alice@example.com"),
                    json={
                        "title": "Scraped Market View",
                        "render_mode": "sandboxed_html",
                        "content_payload": "<html><body>Scraped</body></html>",
                        "allowed_collections": ["scraped_prices"],
                    },
                )
                self.assertEqual(page_resp.status_code, 201, page_resp.text)
                sql_res = client.post(
                    f"/api/pages/{page_resp.json()['slug']}/sql",
                    headers=self._sso("alice@example.com"),
                    json={"sql": "SELECT COUNT(*) AS n, MIN(product) AS first_p FROM dataset"},
                )
                self.assertEqual(sql_res.status_code, 200, sql_res.text)
                self.assertEqual(sql_res.json()["rows"][0]["n"], 250)
                self.assertEqual(sql_res.json()["rows"][0]["first_p"], "Item-000")

                # 2) JSON-LD catalog extraction
                ext_ld = asyncio.run(
                    extract_web_data(
                        "https://shop.example.com/catalog",
                        target_collection="scraped_catalog",
                        repo=repo,
                        fetcher=stub_fetcher,
                    )
                )
                self.assertEqual(ext_ld["status"], "ok")
                self.assertEqual(ext_ld["extraction_kind"], "json_ld")
                self.assertEqual(ext_ld["row_count"], 2)

                # 3) Direct CSV file extraction
                ext_csv = asyncio.run(
                    extract_web_data(
                        "https://files.example.com/market.csv",
                        target_collection="direct_market",
                        repo=repo,
                        fetcher=stub_fetcher,
                    )
                )
                self.assertEqual(ext_csv["status"], "ok")
                self.assertEqual(ext_csv["extraction_kind"], "direct_file")
                self.assertEqual(ext_csv["row_count"], 2)

                # 4) fetch_public_webpage pagination beyond 12,000 chars + JSON-LD + table Markdown
                p1 = asyncio.run(
                    fetch_public_webpage(
                        "https://news.example.com/long-article",
                        repo=repo,
                        fetcher=stub_fetcher,
                        max_chars=12000,
                        offset=0,
                    )
                )
                self.assertTrue(p1["has_more"])
                self.assertEqual(p1["next_offset"], 12000)
                self.assertGreater(p1["total_chars"], 20000)
                self.assertTrue(p1["structured_json_ld"])
                self.assertEqual(p1["structured_json_ld"][0]["headline"], "Cloud Shift")

                p2 = asyncio.run(
                    fetch_public_webpage(
                        "https://news.example.com/long-article",
                        repo=repo,
                        fetcher=stub_fetcher,
                        max_chars=12000,
                        offset=12000,
                    )
                )
                self.assertNotEqual(p1["markdown"], p2["markdown"])
                self.assertGreater(len(p2["markdown"]), 1000)

                # 5) Anti-SSRF private/loopback/metadata IP block remains active
                for blocked_url in (
                    "http://127.0.0.1/admin",
                    "http://169.254.169.254/latest/meta-data/",
                ):
                    with self.assertRaises((SSRFBlockedError, PublicFetchError)):
                        asyncio.run(fetch_public_webpage(blocked_url))

    def test_duckdb_sandbox_security_redaction_and_interrupt_watchdog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp)
            with TestClient(app) as client:
                secret_token = "sk-live-super-secret-token-9999"
                vault_resp = client.post(
                    "/api/vault",
                    headers=self._sso("alice@example.com"),
                    json={
                        "name": "Upstream Token",
                        "secret_type": "api_token",
                        "secrets": {"api_key": secret_token},
                        "allowed_bots": [],
                    },
                )
                self.assertEqual(vault_resp.status_code, 201, vault_resp.text)

                csv_payload = f"id,note\n1,token={secret_token}\n2,normal_row\n".encode("utf-8")
                up_csv = client.post(
                    "/api/files",
                    headers={
                        **self._sso("alice@example.com"),
                        "Content-Type": "text/csv",
                        "X-File-Name": "notes_with_secret.csv",
                    },
                    content=csv_payload,
                )
                self.assertEqual(up_csv.status_code, 201, up_csv.text)
                fid = up_csv.json()["id"]

                page_resp = client.post(
                    "/api/pages",
                    headers=self._sso("alice@example.com"),
                    json={
                        "title": "Security Sandbox Page",
                        "render_mode": "sandboxed_html",
                        "content_payload": "<html><body>Sec</body></html>",
                        "allowed_collections": [f"file:{fid}"],
                    },
                )
                self.assertEqual(page_resp.status_code, 201, page_resp.text)
                page_slug = page_resp.json()["slug"]

                # Vault secret redaction inside query rows
                red_resp = client.post(
                    f"/api/pages/{page_slug}/sql",
                    headers=self._sso("alice@example.com"),
                    json={"sql": "SELECT id, note FROM dataset ORDER BY id"},
                )
                self.assertEqual(red_resp.status_code, 200, red_resp.text)
                serialized = json.dumps(red_resp.json())
                self.assertNotIn(secret_token, serialized)
                self.assertIn("<REDACTED>", serialized)

                # Forbidden SQL keywords, external file reads & sensitive tables -> 403
                forbidden_queries = [
                    "SELECT * FROM read_csv('/etc/passwd')",
                    "SELECT * FROM read_parquet('/etc/passwd')",
                    "SELECT * FROM parquet_scan('other.parquet')",
                    "PRAGMA database_list",
                    "ATTACH ':memory:' AS db2",
                    "COPY dataset TO '/tmp/leak.csv'",
                    "INSTALL httpfs",
                    "SELECT * FROM vault_secrets",
                    "SELECT * FROM sqlite_master",
                    "WITH x AS (SELECT 1) DELETE FROM dataset",
                ]
                for bad_sql in forbidden_queries:
                    r = client.post(
                        f"/api/pages/{page_slug}/sql",
                        headers=self._sso("alice@example.com"),
                        json={"sql": bad_sql},
                    )
                    self.assertEqual(r.status_code, 403, f"Expected 403 for {bad_sql}, got {r.status_code}: {r.text}")

                # Multi-statement query -> 400
                multi_resp = client.post(
                    f"/api/pages/{page_slug}/sql",
                    headers=self._sso("alice@example.com"),
                    json={"sql": "SELECT 1 AS a; SELECT 2 AS b"},
                )
                self.assertEqual(multi_resp.status_code, 400, multi_resp.text)

                # Interrupt watchdog aborts runaway cross-join via conn.interrupt()
                with self.assertRaises(TimeoutError):
                    execute_duckdb_query(
                        "SELECT COUNT(*) AS c FROM range(20000) a, range(20000) b WHERE hash(a.range + b.range) > 0",
                        datasets=[{"id": "empty", "rows": []}],
                        timeout_seconds=0.15,
                    )

                # HTTP 408 mapping on POST /api/pages/{slug}/sql when TimeoutError occurs
                with patch(
                    "argo_core.db.repositories.ArgoRepository.execute_analytics_query",
                    side_effect=TimeoutError("DuckDB sandbox query exceeded the 1.5s time limit."),
                ):
                    timeout_http = client.post(
                        f"/api/pages/{page_slug}/sql",
                        headers=self._sso("alice@example.com"),
                        json={"sql": "SELECT 1"},
                    )
                    self.assertEqual(timeout_http.status_code, 408, timeout_http.text)

    def test_non_avx2_sigill_guard_and_sqlite_analytics_fallback(self) -> None:
        # 1) Simulate SIGILL (-4) when importing duckdb in child probe -> must degrade safely without crashing
        prev_cached = analytics_engine._DUCKDB_RUNTIME_CACHE.copy()
        analytics_engine._DUCKDB_RUNTIME_CACHE.clear()
        try:
            fake_sigill = subprocess.CompletedProcess(args=[], returncode=-4, stdout=b"", stderr=b"")
            with (
                patch.dict(os.environ, {}, clear=False),
                patch.object(analytics_engine, "_has_duckdb_cpu_flags", return_value=True),
                patch.object(analytics_engine.subprocess, "run", return_value=fake_sigill),
            ):
                os.environ.pop("ARGO_DISABLE_DUCKDB", None)
                self.assertFalse(is_duckdb_runtime_supported())
                self.assertIsNone(analytics_engine._get_duckdb())
        finally:
            analytics_engine._DUCKDB_RUNTIME_CACHE.clear()
            analytics_engine._DUCKDB_RUNTIME_CACHE.update(prev_cached)

        # 2) Full fallback path under ARGO_DISABLE_DUCKDB=1 (non-AVX2 VM / container CI mode)
        with patch.dict(os.environ, {"ARGO_DISABLE_DUCKDB": "1"}):
            runtime_info = verify_analytics_runtime()
            self.assertTrue(runtime_info["duckdb_installed"])
            self.assertTrue(runtime_info["sqlite_fallback_verified"])

            queued_actions: list[list[dict[str, Any]]] = []

            async def fake_llm(req: LLMRequest) -> dict[str, Any]:
                del req
                actions = queued_actions.pop(0) if queued_actions else []
                return {
                    "text": json.dumps({"summary": "Fallback PDF read complete.", "actions": actions}),
                    "input_tokens": 15,
                    "output_tokens": 12,
                    "model": "google:gemini-3.8-flash",
                }

            with tempfile.TemporaryDirectory() as tmp:
                app = self._build_env(tmp, llm_transport=fake_llm)
                with TestClient(app) as client:
                    # Upload CSV, multi-sheet .xlsx, and vector PDF without DuckDB
                    csv_bytes = b"region,category,revenue\nNorth,Hardware,100\nNorth,Software,200\nSouth,Hardware,150\n"
                    up_csv = client.post(
                        "/api/files",
                        headers={
                            **self._sso("alice@example.com"),
                            "Content-Type": "text/csv",
                            "X-File-Name": "fallback_sales.csv",
                        },
                        content=csv_bytes,
                    )
                    self.assertEqual(up_csv.status_code, 201, up_csv.text)
                    csv_id = up_csv.json()["id"]

                    xlsx_bytes = _build_test_xlsx_bytes(
                        {
                            "Orders": [["region", "actual_sales"], ["North", 500], ["South", 300]],
                            "Targets": [["region", "target_sales"], ["North", 450], ["South", 350]],
                        }
                    )
                    up_xlsx = client.post(
                        "/api/files",
                        headers={
                            **self._sso("alice@example.com"),
                            "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "X-File-Name": "fallback_quarters.xlsx",
                        },
                        content=xlsx_bytes,
                    )
                    self.assertEqual(up_xlsx.status_code, 201, up_xlsx.text)
                    xlsx_id = up_xlsx.json()["id"]

                    pdf_bytes = _build_multipage_vector_pdf_bytes()
                    up_pdf = client.post(
                        "/api/files",
                        headers={
                            **self._sso("alice@example.com"),
                            "Content-Type": "application/pdf",
                            "X-File-Name": "fallback_report.pdf",
                        },
                        content=pdf_bytes,
                    )
                    self.assertEqual(up_pdf.status_code, 201, up_pdf.text)
                    pdf_id = up_pdf.json()["id"]

                    ws_root = Path(tmp) / "workspace_files"
                    derived_files = list(ws_root.glob(f"*/.derived/{csv_id}/*.parquet"))
                    self.assertTrue(derived_files)
                    for df in derived_files:
                        self.assertEqual(stat.S_IMODE(df.stat().st_mode), 0o444)
                        self.assertTrue(analytics_engine._is_sqlite_store_file(df))

                    page_resp = client.post(
                        "/api/pages",
                        headers=self._sso("alice@example.com"),
                        json={
                            "title": "Portable Analytics Page",
                            "render_mode": "sandboxed_html",
                            "content_payload": "<html><body>Portable</body></html>",
                            "allowed_collections": [
                                f"file:{csv_id}",
                                f"file:{xlsx_id}:sheet_orders",
                                f"file:{xlsx_id}:sheet_targets",
                            ],
                        },
                    )
                    self.assertEqual(page_resp.status_code, 201, page_resp.text)
                    page_slug = page_resp.json()["slug"]

                    data_resp = client.get(
                        f"/api/pages/{page_slug}/data?limit=2000",
                        headers=self._sso("alice@example.com"),
                    )
                    self.assertEqual(data_resp.status_code, 200, data_resp.text)
                    self.assertEqual(len(data_resp.json()["datasets"][f"file:{csv_id}"]), 3)

                    agg_sql = client.post(
                        f"/api/pages/{page_slug}/sql",
                        headers=self._sso("alice@example.com"),
                        json={"sql": "SELECT SUM(revenue) AS total_rev FROM t0", "engine": "auto"},
                    )
                    self.assertEqual(agg_sql.status_code, 200, agg_sql.text)
                    self.assertEqual(agg_sql.json()["engine"], "sqlite")
                    self.assertEqual(agg_sql.json()["rows"][0]["total_rev"], 450)

                    pivot_sql = client.post(
                        f"/api/pages/{page_slug}/sql",
                        headers=self._sso("alice@example.com"),
                        json={
                            "sql": "SELECT * FROM (PIVOT t0 ON category USING SUM(revenue) GROUP BY region) ORDER BY region",
                            "engine": "auto",
                        },
                    )
                    self.assertEqual(pivot_sql.status_code, 200, pivot_sql.text)
                    self.assertEqual(
                        pivot_sql.json()["rows"],
                        [
                            {"region": "North", "Hardware": 100, "Software": 200},
                            {"region": "South", "Hardware": 150, "Software": None},
                        ],
                    )

                    join_sql = client.post(
                        f"/api/pages/{page_slug}/sql",
                        headers=self._sso("alice@example.com"),
                        json={
                            "sql": (
                                "SELECT o.region, o.actual_sales - t.target_sales AS diff "
                                "FROM t1 o JOIN t2 t ON o.region = t.region ORDER BY o.region"
                            ),
                            "engine": "auto",
                        },
                    )
                    self.assertEqual(join_sql.status_code, 200, join_sql.text)
                    self.assertEqual(
                        join_sql.json()["rows"],
                        [{"region": "North", "diff": 50}, {"region": "South", "diff": -50}],
                    )

                    # read_workspace_file with ILIKE search over PDF pages under SQLite fallback
                    bot_resp = client.post(
                        "/api/bots",
                        headers=self._sso("alice@example.com"),
                        json={
                            "name": "Fallback PDF Reader",
                            "role": "Analyst",
                            "outbound_rbac": "internal",
                            "tools": ["read_workspace_file"],
                        },
                    )
                    self.assertEqual(bot_resp.status_code, 201, bot_resp.text)
                    bot_slug = bot_resp.json()["slug"]
                    queued_actions.append(
                        [{"type": "read_workspace_file", "file_id": pdf_id, "query": "fy27forecastmarker"}]
                    )
                    queued_actions.append([])
                    msg_resp = client.post(
                        f"/api/bots/{bot_slug}/messages",
                        headers=self._sso("alice@example.com"),
                        json={"text": "Search PDF", "attachment_ids": [pdf_id]},
                    )
                    self.assertEqual(msg_resp.status_code, 200, msg_resp.text)
                    act = msg_resp.json()["result"]["actions"][0]
                    self.assertEqual(act["status"], "ok")
                    self.assertIn("[Page 3]", act["content"])

                    # Interrupt watchdog on SQLite fallback
                    with self.assertRaises(TimeoutError):
                        execute_duckdb_query(
                            "SELECT COUNT(*) AS c FROM range(20000) a, range(20000) b WHERE hash(a.range + b.range) > 0",
                            datasets=[{"id": "empty", "rows": []}],
                            timeout_seconds=0.15,
                        )

    def test_generative_ui_srcdoc_echarts_runtime_and_48k_page_preview(self) -> None:
        pages_view_ts = (ROOT / "frontend" / "src" / "components" / "views" / "PagesView.tsx").read_text(
            encoding="utf-8"
        )
        echarts_min_path = ROOT / "frontend" / "node_modules" / "echarts" / "dist" / "echarts.min.js"
        world_geo_path = ROOT / "frontend" / "src" / "assets" / "world.geo.json"
        self.assertTrue(echarts_min_path.is_file())
        self.assertTrue(world_geo_path.is_file())

        match = re.search(
            r"const WEBUI_IFRAME_SCROLLBAR_STYLE[\s\S]*?export function prepareSandboxedPageSrcDoc\(rawHtml: string\): string \{[\s\S]*?\n\}",
            pages_view_ts,
        )
        self.assertIsNotNone(match, "prepareSandboxedPageSrcDoc helper slice not found in PagesView.tsx")
        ts_snippet = match.group(0)

        # Transpile TypeScript slice in Node, pass real echarts.min.js + world.geo.json, and execute
        # <script id="argo-echarts"> + <script id="argo-runtime"> inside an isolated vm context.
        node_script = f"""
const fs = require("fs");
const vm = require("vm");
const ts = require({json.dumps(str(ROOT / "frontend" / "node_modules" / "typescript"))});
const src = {json.dumps(ts_snippet)};
const out = ts.transpileModule(src, {{ compilerOptions: {{ module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 }} }}).outputText;
const mod = {{ exports: {{}} }};
new Function("exports", "module", out)(mod.exports, mod);

const echartsScript = fs.readFileSync({json.dumps(str(echarts_min_path))}, "utf8");
const worldGeo = JSON.parse(fs.readFileSync({json.dumps(str(world_geo_path))}, "utf8"));

const rawDash = '<!DOCTYPE html><html><head><title>Geo</title></head><body><div id="c"></div><script>Argo.chart("#c", {{}});</script></body></html>';
const htmlOut = mod.exports.prepareSandboxedPageSrcDoc(rawDash, "light", {{ echartsScript, worldGeo }});

const scriptBlocks = [];
const scriptRe = /<script\\b([^>]*)>([\\s\\S]*?)<\\/script>/gi;
let m;
while ((m = scriptRe.exec(htmlOut)) !== null) {{
  scriptBlocks.push({{ attrs: m[1], body: m[2] }});
}}
const echartsBlock = scriptBlocks.find((s) => s.attrs.includes('id="argo-echarts"'));
const runtimeBlock = scriptBlocks.find((s) => s.attrs.includes('id="argo-runtime"'));

const posted = [];
const listeners = {{}};
const docAttrs = {{}};
const chartNode = {{
  nodeType: 1,
  style: {{}},
  clientWidth: 480,
  clientHeight: 300,
  getAttribute: () => null,
  setAttribute: () => {{}},
  hasAttribute: () => false,
  removeAttribute: () => {{}},
  addEventListener: () => {{}},
  removeEventListener: () => {{}},
  appendChild: () => {{}},
  getBoundingClientRect: () => ({{ width: 480, height: 300, top: 0, left: 0 }}),
}};
const sandboxWin = {{
  addEventListener: (name, fn) => {{ (listeners[name] = listeners[name] || []).push(fn); }},
  parent: {{ postMessage: (msg) => posted.push(msg) }},
  document: {{
    documentElement: {{
      style: {{}},
      getAttribute: (k) => docAttrs[k] || null,
      setAttribute: (k, v) => {{ docAttrs[k] = String(v); }},
    }},
    body: {{ contains: () => true, appendChild: () => {{}}, insertBefore: () => {{}}, firstChild: null }},
    querySelector: () => chartNode,
    getElementById: () => null,
    createElement: (tag) => ({{ tagName: String(tag).toUpperCase(), style: {{}}, appendChild: () => {{}}, setAttribute: () => {{}}, getContext: () => null }}),
  }},
  Intl,
  setTimeout,
  clearTimeout,
  Date,
  Math,
  Number,
  String,
  Array,
  Object,
  JSON,
  Error,
}};
sandboxWin.window = sandboxWin;
sandboxWin.self = sandboxWin;
sandboxWin.globalThis = sandboxWin;
sandboxWin.navigator = {{ userAgent: "node" }};

const ctx = vm.createContext(sandboxWin);
vm.runInContext(echartsBlock.body, ctx);
vm.runInContext(runtimeBlock.body, ctx);

// Trigger setup via Argo.chart with SVG/SSR or catch non-canvas init after setup runs
try {{
  sandboxWin.Argo.chart("#c", {{ series: [{{ type: "map", map: "world", data: [] }}] }}, {{ renderer: "svg", width: 480, height: 300 }});
}} catch (_) {{}}

const worldMap = sandboxWin.echarts.getMap("world");
const currencyStr = sandboxWin.Argo.fmt.currency(1250, "USD");
const externalCover = sandboxWin.Argo.mediaCover("https://cdn.example.com/item.jpg", "Widget Pro");
const dataCover = sandboxWin.Argo.mediaCover("data:image/png;base64,AAAA", "Chart");
sandboxWin.Argo.prefillChat("dash-bot", "Filter Q4");

console.log(JSON.stringify({{
  hasConnectNone: htmlOut.includes("connect-src 'none'"),
  hasImgSrcSafe: htmlOut.includes("img-src data: blob:"),
  hasLightDataTheme: /^<html[^>]*data-theme="light"/i.test(htmlOut.replace("<!DOCTYPE html>", "")),
  hasThemeVars: htmlOut.includes("--bg:#f8fafc") && htmlOut.includes("--series-1:#2563eb"),
  hasEchartsTag: Boolean(echartsBlock),
  hasRuntimeTag: Boolean(runtimeBlock),
  echartsHasRawCloseScript: /<\\/script/i.test(echartsBlock.body),
  runtimeHasRawCloseScript: /<\\/script/i.test(runtimeBlock.body),
  worldFeatureCount: worldMap && worldMap.geoJSON && worldMap.geoJSON.features ? worldMap.geoJSON.features.length : 0,
  currencyStr,
  externalCoverHasImg: /<img\\b/i.test(externalCover),
  externalCoverHasLink: externalCover.includes("https://cdn.example.com/item.jpg"),
  dataCoverHasImg: /<img\\b/i.test(dataCover),
  prefillMsg: posted.find((p) => p && p.type === "ARGO_PREFILL_CHAT") || null,
}}));
"""
        proc = subprocess.run(
            ["node", "-e", node_script],
            check=True,
            capture_output=True,
            text=True,
        )
        res = json.loads(proc.stdout.strip())
        self.assertTrue(res["hasConnectNone"])
        self.assertTrue(res["hasImgSrcSafe"])
        self.assertTrue(res["hasLightDataTheme"])
        self.assertTrue(res["hasThemeVars"])
        self.assertTrue(res["hasEchartsTag"])
        self.assertTrue(res["hasRuntimeTag"])
        self.assertFalse(res["echartsHasRawCloseScript"])
        self.assertFalse(res["runtimeHasRawCloseScript"])
        self.assertEqual(res["worldFeatureCount"], 177)
        self.assertIn("1,250", res["currencyStr"])
        self.assertFalse(res["externalCoverHasImg"])
        self.assertTrue(res["externalCoverHasLink"])
        self.assertTrue(res["dataCoverHasImg"])
        self.assertEqual(
            res["prefillMsg"],
            {"type": "ARGO_PREFILL_CHAT", "botSlug": "dash-bot", "prompt": "Filter Q4"},
        )

        # Verify bot_runner.py passes up to 48,000 chars in target_page.content_preview
        prompts_seen: list[dict[str, Any]] = []

        async def capture_llm(req: LLMRequest) -> dict[str, Any]:
            prompts_seen.append(json.loads(req.user_prompt))
            return {
                "text": json.dumps({"summary": "Checked page payload.", "actions": []}),
                "input_tokens": 20,
                "output_tokens": 10,
                "model": "google:gemini-4-argon",
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=capture_llm)
            with TestClient(app) as client:
                bot_resp = client.post(
                    "/api/bots",
                    headers=self._sso("alice@example.com"),
                    json={
                        "name": "Page Editor",
                        "role": "Editor",
                        "outbound_rbac": "internal",
                        "tools": ["upsert_page"],
                    },
                )
                self.assertEqual(bot_resp.status_code, 201, bot_resp.text)
                bot_slug = bot_resp.json()["slug"]

                large_html = "<div>" + ("X" * 34_980) + "</div><!-- tail-marker -->"
                self.assertGreater(len(large_html), 35_000)
                page_resp = client.post(
                    "/api/pages",
                    headers=self._sso("alice@example.com"),
                    json={
                        "title": "Large Living Page",
                        "render_mode": "sandboxed_html",
                        "owner_bot_slug": bot_slug,
                        "content_payload": large_html,
                    },
                )
                self.assertEqual(page_resp.status_code, 201, page_resp.text)
                page_slug = page_resp.json()["slug"]

                msg_resp = client.post(
                    f"/api/bots/{bot_slug}/messages",
                    headers=self._sso("alice@example.com"),
                    json={"text": "Refine layout.", "target_page_slug": page_slug},
                )
                self.assertEqual(msg_resp.status_code, 200, msg_resp.text)
                self.assertTrue(prompts_seen)
                preview = prompts_seen[0]["target_page"]["content_preview"]
                self.assertEqual(len(preview), len(large_html))
                self.assertTrue(preview.endswith("<!-- tail-marker -->"))

    def test_attached_tabular_csv_omits_text_preview_and_keeps_source_profiles_across_turns(self) -> None:
        captured_prompts: list[dict[str, Any]] = []
        turn_idx = {"n": 0}

        async def two_turn_llm(req: LLMRequest) -> dict[str, Any]:
            captured_prompts.append(json.loads(req.user_prompt))
            turn_idx["n"] += 1
            if turn_idx["n"] == 1:
                return {
                    "text": json.dumps(
                        {
                            "summary": "",
                            "actions": [{"type": "data_query", "sql": "SELECT region, SUM(revenue) AS rev FROM main GROUP BY region"}],
                        }
                    ),
                    "input_tokens": 20,
                    "output_tokens": 14,
                    "model": "google:gemini-3.8-flash",
                }
            return {
                "text": json.dumps(
                    {
                        "summary": "Built revenue table Page.",
                        "actions": [
                            {
                                "type": "upsert_page",
                                "slug": "revenue-table",
                                "title": "Revenue Table",
                                "render_mode": "sandboxed_html",
                                "content_payload": "<!DOCTYPE html><body>Revenue</body></html>",
                            }
                        ],
                    }
                ),
                "input_tokens": 22,
                "output_tokens": 18,
                "model": "google:gemini-3.8-flash",
            }

        with tempfile.TemporaryDirectory() as tmp:
            app = self._build_env(tmp, llm_transport=two_turn_llm)
            with TestClient(app) as client:
                up_csv = client.post(
                    "/api/files",
                    headers={
                        **self._sso("alice@example.com"),
                        "Content-Type": "text/csv",
                        "X-File-Name": "regional_sales.csv",
                    },
                    content=b"region,revenue\nNorth,120\nSouth,80\n",
                )
                self.assertEqual(up_csv.status_code, 201, up_csv.text)
                csv_meta = up_csv.json()
                self.assertTrue(csv_meta.get("derived_datasets"))

                # Plain bot WITHOUT explicit analytics tools still sees source_data_profiles across both turns
                plain_bot = client.post(
                    "/api/bots",
                    headers=self._sso("alice@example.com"),
                    json={
                        "name": "General Helper",
                        "role": "General workspace assistant",
                        "outbound_rbac": "internal",
                        "tools": [],
                    },
                ).json()

                resp = client.post(
                    f"/api/bots/{plain_bot['slug']}/messages",
                    headers=self._sso("alice@example.com"),
                    json={
                        "text": "Put regional sales into a clean table page",
                        "attachment_ids": [csv_meta["id"]],
                    },
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(len(captured_prompts), 2)
                for turn_prompt in captured_prompts:
                    attached = turn_prompt["attached_files"]
                    self.assertEqual(len(attached), 1)
                    self.assertNotIn("text_preview", attached[0])
                    self.assertTrue(turn_prompt.get("source_data_profiles"))
                    self.assertTrue(
                        any(
                            col.get("column_name") == "region"
                            for prof in turn_prompt["source_data_profiles"]
                            for col in prof.get("columns", [])
                        )
                    )


if __name__ == "__main__":
    unittest.main()
