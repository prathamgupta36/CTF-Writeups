import requests
import bleach
from flask import Flask, abort, redirect, render_template, request
from markupsafe import Markup, escape

app = Flask(__name__)

STORIES = []
NEXT_ID = 1

READER_BOT_URL = "http://reader-bot:3000/report"


def sanitize_text(text: str) -> str:
    return bleach.clean(text, tags=[], attributes={}, strip=True)


def linkify_text(text: str) -> str:
    return bleach.linkify(text)


@app.get("/")
def index():
    return render_template("index.html", stories=STORIES)


@app.route("/submit", methods=["GET", "POST"])
def submit():
    global NEXT_ID
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        content = (request.form.get("content") or "").strip()
        default_name = (request.form.get("default_name") or "").strip()
        if not title or not content or not default_name:
            return "Missing fields", 400
        if len(title) > 60 or len(content) > 4000 or len(default_name) > 20:
            return "Too long", 400
        STORIES.append(
            {"id": NEXT_ID, "title": title, "content": content, "default_name": default_name}
        )
        NEXT_ID += 1
        return redirect(f"/read/{NEXT_ID - 1}")
    return render_template("submit.html")


@app.get("/read/<int:story_id>")
def read_story(story_id: int):
    story = next((s for s in STORIES if s["id"] == story_id), None)
    if story is None:
        abort(404)
    name = request.args.get("name") or story["default_name"]
    name = sanitize_text(name.strip())
    content = story["content"].replace("[name]", "[name] ")
    sanitized = sanitize_text(content)
    linkified = linkify_text(sanitized)
    rendered = linkified.replace("[name]", name)
    return render_template(
        "read.html",
        title=escape(story["title"]),
        name=escape(name),
        story=Markup(rendered),
    )


@app.post("/report")
def report():
    story_id = request.form.get("id", "").strip()
    if not story_id.isdigit():
        return "Invalid id", 400
    story_id = int(story_id)
    if not any(s["id"] == story_id for s in STORIES):
        return "Not found", 404
    try:
        requests.post(READER_BOT_URL, json={"id": story_id}, timeout=5)
    except Exception:
        return "Reader failed", 500
    return "A reader is viewing your novel!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
