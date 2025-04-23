# Online Voting System

A secure and user-friendly online voting system built with Flask and modern web technologies.

## Features

- User Authentication (Login/Register)
- Secure Password Hashing
- Active Election Display
- Real-time Vote Casting
- Live Results Display
- Responsive Design
- Mobile-friendly Interface

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd online-voting-system
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory and add your secret key:
```
SECRET_KEY=your-secret-key-here
```

## Running the Application

1. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

2. Run the application:
```bash
python app.py
```

3. Open your web browser and navigate to:
```
http://localhost:5000
```

## Security Features

- Password hashing using Werkzeug's security functions
- Session management with Flask-Login
- CSRF protection
- Input validation and sanitization
- Secure password requirements
- One vote per user per election

## Project Structure

```
online-voting-system/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── .env               # Environment variables
├── static/            # Static files
│   ├── css/          # CSS styles
│   └── js/           # JavaScript files
├── templates/         # HTML templates
└── instance/         # Database and instance-specific files
```

## Contributing

1. Fork the repository
2. Create a new branch for your feature
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Flask web framework
- Bootstrap for the frontend design
- SQLAlchemy for database management 