from toolkit import app
import enhancements  # noqa: F401 - registers extra routes
import ai_tools  # noqa: F401 - registers AI/report routes

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
