# IntelliShare – AI-Enabled Secure File Sharing System

![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python)
![Django](https://img.shields.io/badge/Django-6.0-green?logo=django)
![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-blue?logo=postgresql)
![Machine Learning](https://img.shields.io/badge/AI-Isolation%20Forest-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

**IntelliShare** is a Django-based secure file-sharing web application designed to protect digital files through encryption, controlled access, activity monitoring and AI-based suspicious activity detection.

The system aims to provide a secure environment where users can upload, store, download and share files while maintaining confidentiality, integrity and controlled access. It also uses machine learning techniques to identify potentially unusual user activities and support security monitoring.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Objectives](#objectives)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [AI-Based Suspicious Activity Detection](#ai-based-suspicious-activity-detection)
- [Security Features](#security-features)
- [Project Structure](#project-structure)
- [Installation and Setup](#installation-and-setup)
- [Environment Variables](#environment-variables)
- [Database Setup](#database-setup)
- [Running the Application](#running-the-application)
- [Testing](#testing)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [Author](#author)

---

## Project Overview

Traditional file-sharing platforms may expose sensitive information through unauthorized access, weak access controls, compromised sharing links and insufficient activity monitoring.

IntelliShare addresses these challenges by combining secure file handling with intelligent security monitoring.

The application provides authenticated user access, encrypted file storage, controlled sharing links, file integrity verification, malware scanning and audit logging. Its AI-based security component uses the **Isolation Forest algorithm** to identify unusual activity patterns and assist in detecting potentially suspicious behaviour.

---

## Objectives

- To provide a secure platform for uploading, storing and sharing files.
- To protect file confidentiality through encryption.
- To implement authentication and controlled file-access mechanisms.
- To maintain file integrity using cryptographic hashing.
- To identify suspicious user activities through machine learning.
- To maintain audit logs for security monitoring and investigation.
- To improve visibility into security-related events through a dashboard.

---

## Key Features

### 1. User Authentication and Account Management

- User registration and login.
- Email verification and OTP-based authentication.
- User profile management.
- JWT-based authentication and token management.
- Password management and account security.

### 2. Secure File Management

- Secure file uploading and downloading.
- File encryption before storage.
- AES-256-GCM authenticated encryption.
- SHA-256-based file integrity verification.
- Folder-based file organization.
- Malware scanning integration.

### 3. Controlled File Sharing

- Secure file-sharing links.
- Password-protected sharing.
- Expiry-based access control.
- Download limits.
- Permission-based access.
- Share-link activation and deactivation.

### 4. AI-Based Suspicious Activity Detection

- Activity monitoring through audit logs.
- Extraction of behavioural features from user activities.
- Isolation Forest-based anomaly detection.
- Risk scoring for security events.
- Identification and recording of suspicious incidents.

### 5. Security Monitoring Dashboard

- Security activity monitoring.
- Security incident records.
- Suspicious activity visibility.
- Risk-level information.
- Audit-log tracking.

---

## Technology Stack

| Category | Technologies |
|---|---|
| Backend | Python, Django |
| Frontend | HTML, CSS, JavaScript, Bootstrap |
| Database | PostgreSQL |
| Machine Learning | Scikit-learn, Isolation Forest |
| Encryption | AES-256-GCM |
| Hashing | SHA-256 |
| Authentication | Email OTP, JWT |
| API Framework | Django REST Framework |
| Malware Scanning | ClamAV integration |
| Version Control | Git and GitHub |
| CI/CD | GitHub Actions |

---

## System Architecture

IntelliShare follows a modular architecture in which different application components handle authentication, file management, encryption, sharing and security monitoring.

**Main workflow:**

1. The user registers and authenticates with the application.
2. The user uploads a file through the application.
3. The file undergoes the configured security checks and encryption process.
4. The encrypted file is stored and managed through the file-management module.
5. The owner can create controlled sharing links for other users.
6. User activities are recorded through audit logging.
7. The AI security module analyses relevant activity features to identify potential anomalies.
8. Security incidents and activity information can be reviewed through the security dashboard.

---

## AI-Based Suspicious Activity Detection

IntelliShare incorporates the **Isolation Forest algorithm**, an unsupervised machine learning technique used for anomaly detection.

The model analyses activity-related features to identify patterns that differ from normal user behaviour.

### Features considered

Examples of activity features include:

- Number of events within different time intervals.
- Failed login attempts.
- Failed OTP verification attempts.
- Successful login activity.
- File uploads and downloads.
- Sharing and access-request activity.
- Failed file-access attempts.
- Integrity failures and malware events.
- Number of distinct IP addresses and devices.
- Authentication failure ratio.
- Repeated access to resources.

### Detection workflow

1. Collect relevant user activity through audit logs.
2. Extract numerical features from recorded activities.
3. Prepare feature data for the Isolation Forest model.
4. Generate anomaly predictions.
5. Calculate or evaluate the associated security risk.
6. Record suspicious incidents for further monitoring.

The model supports security monitoring by identifying potentially unusual behaviour. An anomaly prediction should be treated as a security signal rather than definitive proof of malicious activity.

---

## Security Features

| Security Mechanism | Purpose |
|---|---|
| AES-256-GCM | Provides file confidentiality and authenticated encryption |
| SHA-256 | Supports file integrity verification |
| Email OTP | Adds an additional authentication step |
| JWT | Supports token-based authentication |
| Expiry-based links | Restricts sharing access by time |
| Download limits | Controls the number of permitted downloads |
| Password-protected links | Adds protection to shared files |
| Malware scanning | Checks uploaded files for malicious content |
| Audit logging | Maintains records of user activities |
| Isolation Forest | Identifies potentially anomalous activity |

---

## Project Structure

The major directories and files are organized as follows:

```text
IntelliShare/
│
├── accounts/
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   └── audit.py
│
├── encryption/
│   ├── models.py
│   ├── views.py
│   └── encryption utilities
│
├── files/
│   ├── models.py
│   ├── views.py
│   └── file management
│
├── security_ai/
│   ├── models.py
│   ├── management/
│   │   └── commands/
│   │       └── train_security_model.py
│   └── AI security modules
│
├── encryptedFileSharing/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
├── static/
├── templates/
├── tests/
├── docs/
│
├── manage.py
├── requirements.txt
├── pytest.ini
└── README.md
```

*Note: This is a high-level representation. Some subdirectories and files have been omitted for readability.*

---

## Installation and Setup

Follow these steps to run IntelliShare locally.

### 1. Clone the repository

```bash
git clone https://github.com/anjaliagrahari010/IntelliShare.git
```

### 2. Navigate to the project directory

```bash
cd IntelliShare
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

**Windows:**

```bash
venv\Scripts\activate
```

**Linux/macOS:**

```bash
source venv/bin/activate
```

### 5. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 6. Configure environment variables

Create a `.env` file in the project root and configure the required settings.

Refer to the environment variable section below.

### 7. Apply database migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### 8. Create an administrator account

```bash
python manage.py createsuperuser
```

### 9. Run the development server

```bash
python manage.py runserver
```

Open the application in your browser:

```text
http://127.0.0.1:8000/
```

---

## Environment Variables

The application uses environment variables to manage sensitive configuration values.

Create a `.env` file and configure the required values according to your local environment.

```env
DJANGO_SECRET_KEY=your_secret_key
DEBUG=True

DB_NAME=intellishare
DB_USER=postgres
DB_PASSWORD=your_database_password
DB_HOST=localhost
DB_PORT=5432

EMAIL_HOST_USER=your_email_address
EMAIL_HOST_PASSWORD=your_email_app_password
```

**Important:**

- Never upload your actual `.env` file to GitHub.
- Use strong secret keys and database credentials.
- Configure email credentials according to your email provider.
- Use environment variables for production secrets.
- The application also supports database configuration through `DATABASE_URL`.

---

## Database Setup

IntelliShare uses PostgreSQL for database management.

Create a PostgreSQL database before running migrations.

```sql
CREATE DATABASE intellishare;
```

Update the database credentials in your `.env` file and run:

```bash
python manage.py migrate
```

---

## Running Tests

Run Django's test discovery:

```bash
python manage.py test
```

If the project tests are configured with pytest and pytest-django, run:

```bash
pytest
```

Run Django's system check:

```bash
python manage.py check
```

The GitHub Actions workflow is configured to perform automated checks on repository pushes and pull requests.

---

## Future Enhancements

- Integration of advanced machine learning models for improved anomaly detection.
- Improved security analytics and reporting.
- Enhanced file-access revocation mechanisms.
- Cloud storage integration.
- Advanced behavioural analysis and risk assessment.
- Improved user interface and dashboard visualizations.

---

## Contributing

Contributions, suggestions and improvements are welcome.

1. Fork the repository.
2. Create a new feature branch.
3. Make your changes.
4. Test your changes.
5. Submit a pull request.

---

## Author

**Anjali Agrahari**

MCA Student | Python and Django Developer | SAP ABAP Cloud Certified

**Project:** IntelliShare – AI-Enabled Suspicious Activity Detection and File Leakage Analysis on Cloud

**GitHub:** [anjaliagrahari010](https://github.com/anjaliagrahari010)

**Repository:** [IntelliShare](https://github.com/anjaliagrahari010/IntelliShare)

---

*IntelliShare aims to make cloud-based file sharing more secure through encryption, controlled access and intelligent security monitoring.*
