from flask import Flask
from config import Config


app = Flask(__name__)
app.config.from_object(Config)

@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


if __name__ == '__main__':
    app.run()

print("Loaded SECRET_KEY:", app.config['SECRET_KEY'])
print("Loaded ENCRYPTION_KEY:", app.config['ENCRYPTION_KEY'])