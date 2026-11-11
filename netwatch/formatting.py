def format_bytes(num:float) -> str:
    for unit in ("B","KB","MB","GB"):
        if num < 1024 or unit == "GB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024

        