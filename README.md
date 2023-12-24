# Terminal-based-website
This is a smart terminal-based website where normal terminal commands work fine, but users can try human-like sentences like "List all files in the directory" and it will support this too.
# Demo Video - https://www.youtube.com/watch?v=kd6Y1YAf4Cw
## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Endpoints](#endpoints)
- [Technologies Used](#technologies-used)
- [Contributing](#contributing)
- [License](#license)

## Features
- User authentication system (login, signup, logout)
- File manipulation commands (create, read, write, rename, remove directories/files)
- Terminal-like command execution (`ls`, `cd`, `pwd`, etc.)

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/your_username/your_project.git
    ```

2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Set up the database:
    - Ensure you have SQLite installed or update the `SQLALCHEMY_DATABASE_URI` in `app.py` to use another database.

4. Run the application:
    ```bash
    python app.py
    ```

## Usage
- Access the application through your browser at `http://localhost:5001`.
- Register a new account or log in using existing credentials.
- Explore the file manipulation features and terminal-like commands provided.

## Endpoints
- **GET /** - Home page
- **POST /login** - User login
- **GET /logout** - User logout
- **POST /signup** - User signup
- **POST /execute_command** - Execute terminal-like commands

## Technologies Used
- NLTK
- Flask
- SQLAlchemy
- Flask-Bcrypt
- Flask-Login

## Contributing
Contributions are welcome! Here's how you can contribute:
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a pull request

## License
This project is licensed under the [MIT License](LICENSE).
