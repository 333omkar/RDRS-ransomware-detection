import pathlib
p = pathlib.Path("app/dashboard/static/index.html")
text = p.read_text(encoding="utf-8")
old = """function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString();
}"""
new = """function fmtTime(iso) {
  const withZone = iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";
  const d = new Date(withZone);
  return d.toLocaleTimeString();
}"""
if old in text:
    text = text.replace(old, new, 1)
    p.write_text(text, encoding="utf-8")
    print("Patched successfully")
else:
    print("Pattern not found - file may already be patched or modified")
