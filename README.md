# School Bus Safety & Tracking System

A full-stack web application designed to ensure the safety of students using school transport. Built with Node.js and Express, this system uses an intelligent **event-driven architecture**. Instead of relying on expensive, constant-ping GPS hardware, the system dynamically extrapolates the bus's live location when a driver scans a student's QR code at their designated stop.

### Key Features
- **Role-Based Access Control**: Secure, JWT-authenticated portals specifically designed for Admins, Drivers/Staff, and Parents.
- **QR Code Attendance**: Frictionless boarding system that logs 'IN', 'OUT', and 'ABSENT' states while preventing duplicate scans.
- **Event-Driven Live Tracking**: Bus locations automatically update on the Parent Dashboard map whenever a driver scans a student or marks them absent.
- **Automated Parent Linking**: Automatically generates and links parent viewing accounts during the student registration process.
- **Lightweight JSON Database**: Fast, internal file-based (`.json`) storage structure, making the project exceptionally easy to deploy and run locally without setting up SQL/NoSQL servers.

### Tech Stack
- **Backend:** Node.js, Express.js
- **Frontend:** HTML5, Vanilla CSS, JavaScript
- **Database:** Local JSON File I/O
- **Security:** bcryptjs (Password Hashing), jsonwebtoken (Cookies/Session)
