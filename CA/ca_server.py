from flask import Flask

app = Flask(__name__)

@app.route("/")
def server_status():
    return {
        "service": 'CA Server',
        "status": 'Connected'
    }
    
if __name__ == '__main__':
    app.run()
