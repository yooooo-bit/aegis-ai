from app import create_app

app = create_app()

if __name__ == "__main__":
    # Bound to localhost on purpose: this tool should never be exposed to a network.
    app.run(host="127.0.0.1", port=5000, debug=False)
