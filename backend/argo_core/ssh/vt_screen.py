"""Apache-2.0 2D Virtual Terminal Grid & OSC 133 state machine."""

from __future__ import annotations

import codecs
from dataclasses import dataclass, field


@dataclass(slots=True)
class _BufferState:
    cols: int
    rows: int
    grid: list[list[str]] = field(default_factory=list)
    cursor_row: int = 0
    cursor_col: int = 0
    saved_row: int = 0
    saved_col: int = 0
    scroll_top: int = 0
    scroll_bottom: int = 0
    wrap_pending: bool = False

    def __post_init__(self) -> None:
        if not self.grid:
            self.grid = [[" "] * self.cols for _ in range(self.rows)]
        self.scroll_bottom = max(0, self.rows - 1)


class VirtualTerminalScreen:
    """Self-contained 2D ANSI/VT100 terminal screen buffer with OSC 133 command framing."""

    def __init__(self, cols: int = 120, rows: int = 36, max_scrollback: int = 500) -> None:
        self.cols = max(20, int(cols))
        self.rows = max(5, int(rows))
        self.max_scrollback = max(0, int(max_scrollback))

        self._primary = _BufferState(cols=self.cols, rows=self.rows)
        self._alternate = _BufferState(cols=self.cols, rows=self.rows)
        self._using_alternate = False
        self.scrollback: list[str] = []

        self._utf8_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._state = "ground"  # ground | esc | csi | osc | osc_esc | dcs | dcs_esc | charset
        self._esc_buf = ""

        self.last_exit_code: int | None = None
        self.command_completed_seq: int = 0
        self.last_char_was_newline: bool = True

    @property
    def _buf(self) -> _BufferState:
        return self._alternate if self._using_alternate else self._primary

    @property
    def cursor_row(self) -> int:
        return self._buf.cursor_row

    @property
    def cursor_col(self) -> int:
        return self._buf.cursor_col

    def reset(self) -> None:
        """Clear primary/alternate grids, scrollback, and pending parser buffers."""
        self._primary = _BufferState(cols=self.cols, rows=self.rows)
        self._alternate = _BufferState(cols=self.cols, rows=self.rows)
        self._using_alternate = False
        self.scrollback.clear()
        self._utf8_decoder.reset()
        self._state = "ground"
        self._esc_buf = ""
        self.last_char_was_newline = True

    def clear_history_keep_prompt(self) -> None:
        """Clear pre-bootstrap banner/noise while preserving the active shell prompt and cursor column."""
        cur_buf = self._buf
        prompt_row = list(cur_buf.grid[cur_buf.cursor_row])
        saved_col = max(0, min(self.cols - 1, cur_buf.cursor_col))
        saved_wrap = cur_buf.wrap_pending
        saved_last_nl = self.last_char_was_newline

        self._primary = _BufferState(cols=self.cols, rows=self.rows)
        self._alternate = _BufferState(cols=self.cols, rows=self.rows)
        self._using_alternate = False
        self.scrollback.clear()
        self._utf8_decoder.reset()
        self._state = "ground"
        self._esc_buf = ""

        if "".join(prompt_row).strip() or saved_col > 0:
            self._primary.grid[0] = prompt_row
            self._primary.cursor_row = 0
            self._primary.cursor_col = saved_col
            self._primary.wrap_pending = saved_wrap
            self.last_char_was_newline = saved_last_nl
        else:
            self.last_char_was_newline = True

    def resize(self, cols: int, rows: int) -> None:
        """Resize both terminal screen buffers while preserving visible contents."""
        new_cols = max(20, int(cols))
        new_rows = max(5, int(rows))
        if new_cols == self.cols and new_rows == self.rows:
            return
        self.cols = new_cols
        self.rows = new_rows
        for buf in (self._primary, self._alternate):
            new_grid = [[" "] * new_cols for _ in range(new_rows)]
            for r in range(min(buf.rows, new_rows)):
                row_data = buf.grid[r]
                limit = min(len(row_data), new_cols)
                new_grid[r][:limit] = row_data[:limit]
            buf.cols = new_cols
            buf.rows = new_rows
            buf.grid = new_grid
            buf.cursor_row = min(buf.cursor_row, new_rows - 1)
            buf.cursor_col = min(buf.cursor_col, new_cols - 1)
            buf.saved_row = min(buf.saved_row, new_rows - 1)
            buf.saved_col = min(buf.saved_col, new_cols - 1)
            buf.scroll_top = 0
            buf.scroll_bottom = new_rows - 1
            buf.wrap_pending = False

    def _scroll_up(self, count: int = 1) -> None:
        buf = self._buf
        top = max(0, min(buf.scroll_top, buf.rows - 1))
        bottom = max(top, min(buf.scroll_bottom, buf.rows - 1))
        for _ in range(max(1, count)):
            if not self._using_alternate and top == 0 and self.max_scrollback > 0:
                line = "".join(buf.grid[0]).rstrip()
                self.scrollback.append(line)
                if len(self.scrollback) > self.max_scrollback:
                    del self.scrollback[0 : len(self.scrollback) - self.max_scrollback]
            for r in range(top, bottom):
                buf.grid[r] = buf.grid[r + 1]
            buf.grid[bottom] = [" "] * buf.cols

    def _scroll_down(self, count: int = 1) -> None:
        buf = self._buf
        top = max(0, min(buf.scroll_top, buf.rows - 1))
        bottom = max(top, min(buf.scroll_bottom, buf.rows - 1))
        for _ in range(max(1, count)):
            for r in range(bottom, top, -1):
                buf.grid[r] = buf.grid[r - 1]
            buf.grid[top] = [" "] * buf.cols

    def _line_feed(self) -> None:
        buf = self._buf
        buf.wrap_pending = False
        if buf.cursor_row == buf.scroll_bottom:
            self._scroll_up(1)
        elif buf.cursor_row < buf.rows - 1:
            buf.cursor_row += 1
        self.last_char_was_newline = True

    def _put_char(self, ch: str) -> None:
        buf = self._buf
        if buf.wrap_pending:
            buf.cursor_col = 0
            if buf.cursor_row == buf.scroll_bottom:
                self._scroll_up(1)
            elif buf.cursor_row < buf.rows - 1:
                buf.cursor_row += 1
            buf.wrap_pending = False
        buf.grid[buf.cursor_row][buf.cursor_col] = ch
        if buf.cursor_col >= buf.cols - 1:
            buf.wrap_pending = True
        else:
            buf.cursor_col += 1
        self.last_char_was_newline = False

    @staticmethod
    def _parse_params(raw: str, default: int = 0) -> list[int]:
        if not raw:
            return [default]
        out: list[int] = []
        for part in raw.split(";"):
            if part == "":
                out.append(default)
            else:
                try:
                    out.append(int(part))
                except ValueError:
                    out.append(default)
        return out

    def _handle_csi(self, seq: str) -> None:
        if not seq:
            return
        final = seq[-1]
        body = seq[:-1]
        buf = self._buf

        if body.startswith("?"):
            modes = self._parse_params(body[1:], default=0)
            if final in ("h", "l"):
                enable = final == "h"
                for m in modes:
                    if m in (47, 1047, 1049):
                        if enable and not self._using_alternate:
                            self._primary.saved_row = self._primary.cursor_row
                            self._primary.saved_col = self._primary.cursor_col
                            self._alternate = _BufferState(cols=self.cols, rows=self.rows)
                            self._using_alternate = True
                        elif not enable and self._using_alternate:
                            self._using_alternate = False
                            self._primary.cursor_row = min(
                                self._primary.saved_row, self._primary.rows - 1
                            )
                            self._primary.cursor_col = min(
                                self._primary.saved_col, self._primary.cols - 1
                            )
                            self._primary.wrap_pending = False
            return

        if body.startswith((">", "=", "!")):
            return

        # Strip intermediate characters like spaces/quotes if present
        param_str = "".join(ch for ch in body if ch.isdigit() or ch == ";")
        buf.wrap_pending = False

        if final == "m":
            return
        if final in ("A", "B", "C", "D"):
            n = max(1, self._parse_params(param_str, 1)[0])
            if final == "A":
                buf.cursor_row = max(buf.scroll_top, buf.cursor_row - n)
            elif final == "B":
                buf.cursor_row = min(buf.scroll_bottom, buf.cursor_row + n)
            elif final == "C":
                buf.cursor_col = min(buf.cols - 1, buf.cursor_col + n)
            elif final == "D":
                buf.cursor_col = max(0, buf.cursor_col - n)
            return
        if final in ("E", "F"):
            n = max(1, self._parse_params(param_str, 1)[0])
            buf.cursor_col = 0
            if final == "E":
                buf.cursor_row = min(buf.scroll_bottom, buf.cursor_row + n)
            else:
                buf.cursor_row = max(buf.scroll_top, buf.cursor_row - n)
            return
        if final in ("G", "`"):
            col = max(1, self._parse_params(param_str, 1)[0]) - 1
            buf.cursor_col = min(buf.cols - 1, col)
            return
        if final == "d":
            row = max(1, self._parse_params(param_str, 1)[0]) - 1
            buf.cursor_row = min(buf.rows - 1, row)
            return
        if final in ("H", "f"):
            parts = param_str.split(";") if param_str else []
            row = (int(parts[0]) if len(parts) >= 1 and parts[0] else 1) - 1
            col = (int(parts[1]) if len(parts) >= 2 and parts[1] else 1) - 1
            buf.cursor_row = max(0, min(buf.rows - 1, row))
            buf.cursor_col = max(0, min(buf.cols - 1, col))
            return
        if final == "J":
            mode = self._parse_params(param_str, 0)[0]
            if mode == 0:
                for c in range(buf.cursor_col, buf.cols):
                    buf.grid[buf.cursor_row][c] = " "
                for r in range(buf.cursor_row + 1, buf.rows):
                    buf.grid[r] = [" "] * buf.cols
            elif mode == 1:
                for r in range(0, buf.cursor_row):
                    buf.grid[r] = [" "] * buf.cols
                for c in range(0, buf.cursor_col + 1):
                    buf.grid[buf.cursor_row][c] = " "
            elif mode in (2, 3):
                buf.grid = [[" "] * buf.cols for _ in range(buf.rows)]
                if mode == 3 and not self._using_alternate:
                    self.scrollback.clear()
            return
        if final == "K":
            mode = self._parse_params(param_str, 0)[0]
            if mode == 0:
                for c in range(buf.cursor_col, buf.cols):
                    buf.grid[buf.cursor_row][c] = " "
            elif mode == 1:
                for c in range(0, buf.cursor_col + 1):
                    buf.grid[buf.cursor_row][c] = " "
            elif mode == 2:
                buf.grid[buf.cursor_row] = [" "] * buf.cols
            return
        if final == "X":
            n = max(1, self._parse_params(param_str, 1)[0])
            for c in range(buf.cursor_col, min(buf.cols, buf.cursor_col + n)):
                buf.grid[buf.cursor_row][c] = " "
            return
        if final == "P":
            n = max(1, self._parse_params(param_str, 1)[0])
            row = buf.grid[buf.cursor_row]
            del row[buf.cursor_col : buf.cursor_col + n]
            row.extend([" "] * min(n, buf.cols - len(row)))
            return
        if final == "@":
            n = max(1, self._parse_params(param_str, 1)[0])
            row = buf.grid[buf.cursor_row]
            buf.grid[buf.cursor_row] = (
                row[: buf.cursor_col] + ([" "] * n) + row[buf.cursor_col :]
            )[: buf.cols]
            return
        if final == "L":
            n = max(1, self._parse_params(param_str, 1)[0])
            if buf.scroll_top <= buf.cursor_row <= buf.scroll_bottom:
                for _ in range(n):
                    for r in range(buf.scroll_bottom, buf.cursor_row, -1):
                        buf.grid[r] = buf.grid[r - 1]
                    buf.grid[buf.cursor_row] = [" "] * buf.cols
            return
        if final == "M":
            n = max(1, self._parse_params(param_str, 1)[0])
            if buf.scroll_top <= buf.cursor_row <= buf.scroll_bottom:
                for _ in range(n):
                    for r in range(buf.cursor_row, buf.scroll_bottom):
                        buf.grid[r] = buf.grid[r + 1]
                    buf.grid[buf.scroll_bottom] = [" "] * buf.cols
            return
        if final == "S":
            self._scroll_up(max(1, self._parse_params(param_str, 1)[0]))
            return
        if final == "T":
            self._scroll_down(max(1, self._parse_params(param_str, 1)[0]))
            return
        if final == "r":
            parts = param_str.split(";") if param_str else []
            top = (int(parts[0]) if len(parts) >= 1 and parts[0] else 1) - 1
            bottom = (int(parts[1]) if len(parts) >= 2 and parts[1] else buf.rows) - 1
            top = max(0, min(buf.rows - 1, top))
            bottom = max(top, min(buf.rows - 1, bottom))
            buf.scroll_top = top
            buf.scroll_bottom = bottom
            buf.cursor_row = 0
            buf.cursor_col = 0
            return
        if final == "s":
            buf.saved_row = buf.cursor_row
            buf.saved_col = buf.cursor_col
            return
        if final == "u":
            buf.cursor_row = min(buf.rows - 1, buf.saved_row)
            buf.cursor_col = min(buf.cols - 1, buf.saved_col)
            return

    def _handle_osc(self, payload: str, exit_codes: list[int]) -> None:
        if not payload.startswith("133;"):
            return
        parts = payload.split(";")
        kind = parts[1] if len(parts) > 1 else ""
        if kind == "D":
            code = 0
            if len(parts) > 2 and parts[2].strip():
                try:
                    code = int(parts[2].strip())
                except ValueError:
                    code = 0
            self.last_exit_code = code
            self.command_completed_seq += 1
            exit_codes.append(code)

    def feed(self, data: bytes | str) -> list[int]:
        """Feed raw terminal bytes or text into the 2D screen; return observed OSC 133;D codes."""
        if isinstance(data, (bytes, bytearray, memoryview)):
            text = self._utf8_decoder.decode(bytes(data), final=False)
        else:
            text = str(data)

        exit_codes: list[int] = []
        buf = self._buf

        for ch in text:
            buf = self._buf
            if self._state == "ground":
                if ch == "\x1b":
                    self._state = "esc"
                    self._esc_buf = ""
                elif ch == "\r":
                    buf.cursor_col = 0
                    buf.wrap_pending = False
                elif ch in ("\n", "\v", "\f"):
                    self._line_feed()
                elif ch == "\b":
                    buf.cursor_col = max(0, buf.cursor_col - 1)
                    buf.wrap_pending = False
                elif ch == "\t":
                    next_tab = ((buf.cursor_col // 8) + 1) * 8
                    buf.cursor_col = min(buf.cols - 1, next_tab)
                    buf.wrap_pending = False
                elif ch == "\x07" or ord(ch) < 32 or ord(ch) == 127:
                    continue
                else:
                    self._put_char(ch)
            elif self._state == "esc":
                if ch == "[":
                    self._state = "csi"
                    self._esc_buf = ""
                elif ch == "]":
                    self._state = "osc"
                    self._esc_buf = ""
                elif ch in ("P", "_", "^"):
                    self._state = "dcs"
                    self._esc_buf = ""
                elif ch in ("(", ")", "*", "+"):
                    self._state = "charset"
                elif ch == "7":
                    buf.saved_row = buf.cursor_row
                    buf.saved_col = buf.cursor_col
                    self._state = "ground"
                elif ch == "8":
                    buf.cursor_row = min(buf.rows - 1, buf.saved_row)
                    buf.cursor_col = min(buf.cols - 1, buf.saved_col)
                    buf.wrap_pending = False
                    self._state = "ground"
                elif ch == "M":
                    if buf.cursor_row == buf.scroll_top:
                        self._scroll_down(1)
                    elif buf.cursor_row > 0:
                        buf.cursor_row -= 1
                    self._state = "ground"
                elif ch == "D":
                    self._line_feed()
                    self._state = "ground"
                elif ch == "E":
                    buf.cursor_col = 0
                    self._line_feed()
                    self._state = "ground"
                elif ch == "c":
                    self.reset()
                else:
                    self._state = "ground"
            elif self._state == "charset":
                self._state = "ground"
            elif self._state == "csi":
                self._esc_buf += ch
                if "@" <= ch <= "~":
                    self._handle_csi(self._esc_buf)
                    self._state = "ground"
                    self._esc_buf = ""
                elif len(self._esc_buf) > 256:
                    self._state = "ground"
                    self._esc_buf = ""
            elif self._state == "osc":
                if ch == "\x07":
                    self._handle_osc(self._esc_buf, exit_codes)
                    self._state = "ground"
                    self._esc_buf = ""
                elif ch == "\x1b":
                    self._state = "osc_esc"
                else:
                    if len(self._esc_buf) < 4096:
                        self._esc_buf += ch
            elif self._state == "osc_esc":
                if ch == "\\":
                    self._handle_osc(self._esc_buf, exit_codes)
                    self._state = "ground"
                    self._esc_buf = ""
                else:
                    self._state = "osc"
                    if len(self._esc_buf) < 4096:
                        self._esc_buf += "\x1b" + ch
            elif self._state == "dcs":
                if ch == "\x1b":
                    self._state = "dcs_esc"
                elif ch == "\x07":
                    self._state = "ground"
            elif self._state == "dcs_esc":
                if ch == "\\":
                    self._state = "ground"
                else:
                    self._state = "dcs"

        return exit_codes

    def render_text(
        self,
        include_cursor_line: bool = True,
        include_scrollback_lines: int = 0,
    ) -> str:
        """Return right-trimmed visible viewport lines (optionally with trailing scrollback)."""
        buf = self._buf
        lines = ["".join(row).rstrip() for row in buf.grid]
        last_non_empty = -1
        for idx, line in enumerate(lines):
            if line:
                last_non_empty = idx
        if include_cursor_line:
            last_non_empty = max(last_non_empty, min(buf.cursor_row, len(lines) - 1))
        visible = lines[: last_non_empty + 1] if last_non_empty >= 0 else []
        if include_scrollback_lines > 0 and not self._using_alternate and self.scrollback:
            sb = self.scrollback[-include_scrollback_lines:]
            visible = [*sb, *visible]
        return "\n".join(visible).rstrip("\n")

    def tail_prompt_line(self) -> str:
        """Return the trimmed active cursor line (or last non-empty row) for prompt detection."""
        buf = self._buf
        active = "".join(buf.grid[buf.cursor_row]).rstrip()
        if active:
            return active
        for row in reversed(buf.grid):
            txt = "".join(row).rstrip()
            if txt:
                return txt
        return ""
