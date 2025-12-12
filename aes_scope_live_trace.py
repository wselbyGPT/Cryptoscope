#!/usr/bin/env python3
"""
aes_scope_live_trace.py — live AES-128 round animation with scrolling HW trace.

- AES-128: 128-bit block, 128-bit key, 10 rounds.
- For each cycle:
    * Plaintext = base_pt XOR counter (big-endian)
    * Encrypt with AES-128, capturing round states (0..10)
    * Each round state is one animation frame
    * Each frame contributes a point to a scrolling Hamming-weight trace
    * Counter increments and repeats

Display per frame:
    * Key, plaintext, ciphertext, block counter
    * Current round label
    * Hamming weight and delta vs previous state
    * Horizontal bar for instantaneous Hamming weight
    * Scrolling oscilloscope-style trace of HW over recent frames
    * 4×4 AES state matrix (hex)

Controls:
    * q / Q  -> quit
"""

import argparse
import time
import curses

# ---------- AES constants (AES-128) ----------

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

RCON = [
    0x00,
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
]

# ---------- AES core helpers ----------

def bytes_to_state(block: bytes):
    """16 bytes -> 4x4 AES state (row, col), column-major mapping."""
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = block[i]
    return state


def state_to_bytes(state):
    out = []
    for col in range(4):
        for row in range(4):
            out.append(state[row][col] & 0xFF)
    return bytes(out)


def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]


def shift_rows(state):
    for r in range(1, 4):
        row = state[r]
        state[r] = row[r:] + row[:r]


def xtime(a: int) -> int:
    a &= 0xFF
    if a & 0x80:
        return ((a << 1) ^ 0x1B) & 0xFF
    else:
        return (a << 1) & 0xFF


def mix_single_column(col):
    a0, a1, a2, a3 = col
    m2 = [xtime(x) for x in (a0, a1, a2, a3)]
    m3 = [m2[i] ^ col[i] for i in range(4)]
    r0 = m2[0] ^ m3[1] ^ a2      ^ a3
    r1 = a0      ^ m2[1] ^ m3[2] ^ a3
    r2 = a0      ^ a1      ^ m2[2] ^ m3[3]
    r3 = m3[0] ^ a1      ^ a2      ^ m2[3]
    return [r0 & 0xFF, r1 & 0xFF, r2 & 0xFF, r3 & 0xFF]


def mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        col = mix_single_column(col)
        for r in range(4):
            state[r][c] = col[r]


def add_round_key(state, round_key: bytes):
    if len(round_key) != 16:
        raise ValueError("Round key must be 16 bytes")
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] ^= round_key[i]


def rot_word(word):
    return word[1:] + word[:1]


def sub_word(word):
    return [S_BOX[b] for b in word]


def key_expansion_128(key: bytes):
    """AES-128 key expansion: 16-byte key -> 11 round keys (16 bytes each)."""
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    Nk = 4
    Nb = 4
    Nr = 10
    total_words = Nb * (Nr + 1)
    w = [[0, 0, 0, 0] for _ in range(total_words)]

    for i in range(Nk):
        w[i][0] = key[4 * i + 0]
        w[i][1] = key[4 * i + 1]
        w[i][2] = key[4 * i + 2]
        w[i][3] = key[4 * i + 3]

    for i in range(Nk, total_words):
        temp = w[i - 1][:]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // Nk]
        w[i] = [(w[i - Nk][j] ^ temp[j]) & 0xFF for j in range(4)]

    round_keys = []
    for r in range(Nr + 1):
        rk = []
        for c in range(Nb):
            rk.extend(w[r * Nb + c])
        round_keys.append(bytes(rk))
    return round_keys


def clone_state(state):
    return [row[:] for row in state]


def flatten_state(state):
    return [state[r][c] for c in range(4) for r in range(4)]


def hamming_weight_bytes(byte_list):
    return sum(b.bit_count() for b in byte_list)


def aes128_encrypt_with_states(block: bytes, key: bytes):
    """
    Encrypt a 16-byte block with AES-128, capturing state after each round.

    Returns: (ciphertext, rounds)
      rounds: list of dicts { "round", "label", "state" }
    """
    Nr = 10
    round_keys = key_expansion_128(key)

    state = bytes_to_state(block)
    rounds = []

    # Round 0: AddRoundKey
    add_round_key(state, round_keys[0])
    rounds.append({
        "round": 0,
        "label": "Round 0 (AddRoundKey)",
        "state": clone_state(state),
    })

    # Rounds 1..Nr-1: SubBytes, ShiftRows, MixColumns, AddRoundKey
    for rnd in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])
        rounds.append({
            "round": rnd,
            "label": f"Round {rnd}",
            "state": clone_state(state),
        })

    # Final round Nr: no MixColumns
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[Nr])
    rounds.append({
        "round": Nr,
        "label": f"Round {Nr} (final)",
        "state": clone_state(state),
    })

    cipher = state_to_bytes(state)
    return cipher, rounds

# ---------- Visualization helpers ----------

def format_state_hex_lines(state):
    lines = []
    for r in range(4):
        line = " ".join(f"{state[r][c]:02X}" for c in range(4))
        lines.append(line)
    return lines


def make_bar(value: int, max_value: int, width: int):
    if max_value <= 0:
        return " " * width
    value = max(0, min(max_value, value))
    frac = value / max_value
    n_filled = int(round(frac * width))
    n_filled = min(width, max(0, n_filled))
    filled_char = "█"
    empty_char = " "
    return filled_char * n_filled + empty_char * (width - n_filled)

# ---------- Curses helpers ----------

COLOR_TITLE = 1
COLOR_LABEL = 2
COLOR_VALUE = 3
COLOR_DELTA = 4
COLOR_BAR   = 5
COLOR_ROUND = 6
COLOR_TRACE = 7

def init_colors():
    if not curses.has_colors():
        return False
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(COLOR_TITLE, curses.COLOR_CYAN, -1)
    curses.init_pair(COLOR_LABEL, curses.COLOR_YELLOW, -1)
    curses.init_pair(COLOR_VALUE, curses.COLOR_GREEN, -1)
    curses.init_pair(COLOR_DELTA, curses.COLOR_MAGENTA, -1)
    curses.init_pair(COLOR_BAR,   curses.COLOR_RED, -1)
    curses.init_pair(COLOR_ROUND, curses.COLOR_BLUE, -1)
    curses.init_pair(COLOR_TRACE, curses.COLOR_GREEN, -1)
    return True


def addstr_safe(stdscr, y, x, text, attr=0):
    try:
        stdscr.addstr(y, x, text, attr)
    except curses.error:
        pass

# ---------- CLI ----------

def parse_hex_bytes(s: str, expected_len: int, what: str) -> bytes:
    s = s.strip().replace(" ", "").replace("_", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) != expected_len * 2:
        raise SystemExit(
            f"{what} must be exactly {expected_len} bytes ({expected_len*2} hex digits), "
            f"got {len(s)} hex digits."
        )
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise SystemExit(f"Invalid hex for {what}: {s!r}")


def parse_args():
    p = argparse.ArgumentParser(
        description="Live AES-128 round animation with Hamming-weight trace (curses).",
    )
    p.add_argument(
        "--pt-hex",
        default="00112233445566778899AABBCCDDEEFF",
        help="Base plaintext (16 bytes hex, default: 00112233445566778899AABBCCDDEEFF)",
    )
    p.add_argument(
        "--key-hex",
        default="000102030405060708090A0B0C0D0E0F",
        help="AES-128 key (16 bytes hex, default: 000102030405060708090A0B0C0D0E0F)",
    )
    p.add_argument(
        "--fps",
        type=float,
        default=10.0,
        help="Frames per second (default: 10.0)",
    )
    p.add_argument(
        "--trace-height",
        type=int,
        default=8,
        help="Maximum height (in rows) of the HW trace (default: 8)",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable curses color",
    )
    return p.parse_args()

# ---------- Curses main loop ----------

def run_curses(stdscr, key: bytes, base_pt: bytes, fps: float, use_color_flag: bool, trace_height_param: int):
    curses.curs_set(0)
    stdscr.nodelay(True)

    colors_enabled = False
    if use_color_flag:
        colors_enabled = init_colors()

    max_hw = 128
    counter = 0
    frame_delay = 1.0 / max(1e-3, fps)

    trace_hw = []               # Hamming weights over time
    TRACE_BUFFER_MAX = 2048     # cap buffer to avoid unbounded growth

    while True:
        # Construct plaintext = base_pt XOR counter (big-endian)
        base_int = int.from_bytes(base_pt, "big")
        pt_int = base_int ^ counter
        pt = pt_int.to_bytes(16, "big")

        cipher, rounds = aes128_encrypt_with_states(pt, key)
        prev_flat = None

        for rd in rounds:
            ch = stdscr.getch()
            if ch in (ord('q'), ord('Q')):
                return

            state = rd["state"]
            label = rd["label"]
            flat = flatten_state(state)
            hw_total = hamming_weight_bytes(flat)
            if prev_flat is None:
                hw_delta = 0
            else:
                delta_bytes = [a ^ b for a, b in zip(flat, prev_flat)]
                hw_delta = hamming_weight_bytes(delta_bytes)
            prev_flat = flat

            # Append to trace
            trace_hw.append(hw_total)
            if len(trace_hw) > TRACE_BUFFER_MAX:
                trace_hw.pop(0)

            max_y, max_x = stdscr.getmaxyx()
            stdscr.erase()

            # Dynamic bar width
            bar_width = max(10, max_x - 20)

            # Color attrs
            title_attr = curses.color_pair(COLOR_TITLE) | curses.A_BOLD if colors_enabled else curses.A_BOLD
            label_attr = curses.color_pair(COLOR_LABEL) | curses.A_BOLD if colors_enabled else curses.A_BOLD
            value_attr = curses.color_pair(COLOR_VALUE) if colors_enabled else 0
            delta_attr = curses.color_pair(COLOR_DELTA) if colors_enabled else 0
            bar_attr   = curses.color_pair(COLOR_BAR)   if colors_enabled else 0
            round_attr = curses.color_pair(COLOR_ROUND) | curses.A_BOLD if colors_enabled else curses.A_BOLD
            trace_attr = curses.color_pair(COLOR_TRACE) if colors_enabled else 0

            # Header area
            y = 0
            addstr_safe(stdscr, y, 2, "AES-128 LIVE ROUND SCOPE (HW trace)", title_attr)
            y += 1
            addstr_safe(stdscr, y, 2, "q = quit", label_attr)
            y += 1

            addstr_safe(stdscr, y, 2, "Key: ", label_attr)
            addstr_safe(stdscr, y, 8, key.hex().upper(), value_attr)
            y += 1

            addstr_safe(stdscr, y, 2, "Plaintext: ", label_attr)
            addstr_safe(stdscr, y, 13, pt.hex().upper(), value_attr)
            y += 1

            addstr_safe(stdscr, y, 2, "Ciphertext:", label_attr)
            addstr_safe(stdscr, y, 13, cipher.hex().upper(), value_attr)
            y += 1

            addstr_safe(stdscr, y, 2, "Block counter:", label_attr)
            addstr_safe(stdscr, y, 17, str(counter), value_attr)
            y += 1

            # Round info + instantaneous HW bar
            addstr_safe(stdscr, y, 2, label, round_attr)
            y += 1

            hw_text = f"HW={hw_total:3d}   HW(Δ)={hw_delta:3d}"
            addstr_safe(stdscr, y, 2, hw_text, delta_attr)
            y += 1

            bar = make_bar(hw_total, max_hw, bar_width)
            addstr_safe(stdscr, y, 2, "[" + bar + "]", bar_attr)
            y += 1

            # ---- HW trace (oscilloscope) ----
            trace_top = y + 1
            # Reserve space for trace + 4 state rows + a couple of gaps
            reserved_for_state = 4 + 2
            available_lines = max_y - trace_top - reserved_for_state
            if available_lines >= 3 and trace_hw:
                trace_height = min(trace_height_param, available_lines)
                trace_bottom = trace_top + trace_height - 1

                # Draw vertical axis
                for row in range(trace_height):
                    addstr_safe(stdscr, trace_top + row, 2, "|", label_attr)
                addstr_safe(stdscr, trace_bottom, 2, "+", label_attr)

                # Determine horizontal trace width
                trace_width = max_x - 6
                if trace_width > 0:
                    cols_to_draw = min(trace_width, len(trace_hw))
                    start_index = len(trace_hw) - cols_to_draw

                    for i in range(cols_to_draw):
                        val = trace_hw[start_index + i]
                        # Map HW [0..max_hw] -> level [0..trace_height-1]
                        level = int(round((val / max_hw) * (trace_height - 1)))
                        level = max(0, min(trace_height - 1, level))
                        row = trace_bottom - level
                        x = 3 + i
                        addstr_safe(stdscr, row, x, "█", trace_attr)

                y = trace_bottom + 2
            else:
                # Not enough room or no data — skip trace
                y = trace_top

            # ---- State matrix at bottom ----
            lines = format_state_hex_lines(state)
            for r_idx, line in enumerate(lines):
                if y >= max_y - 1:
                    break
                addstr_safe(stdscr, y, 4, f"row{r_idx}: ", label_attr)
                addstr_safe(stdscr, y, 12, line, value_attr)
                y += 1

            stdscr.refresh()
            time.sleep(frame_delay)

        counter += 1

# ---------- Entry ----------

def main():
    args = parse_args()
    key = parse_hex_bytes(args.key_hex, 16, "Key (AES-128)")
    base_pt = parse_hex_bytes(args.pt_hex, 16, "Base plaintext")
    use_color_flag = not args.no_color
    curses.wrapper(run_curses, key, base_pt, args.fps, use_color_flag, args.trace_height)


if __name__ == "__main__":
    main()
