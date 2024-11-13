# Auth Server

This project is a Node.js server. Follow the instructions below to run and configure the server.

## Getting Started

### Prerequisites

Make sure you have Node.js and npm installed. You can download them from [Node.js official website](https://nodejs.org/).

### Installation

1. Clone the repository:
   ```bash
   git clone <your-repository-url>
   ```
2. Navigate to the project directory:
   ```bash
   cd <your-project-directory>
   ```
3. Install the dependencies:
   ```bash
   npm install
   ```
4. Download firebase-adminsdk.json from this [link](https://drive.google.com/drive/folders/1M1r1Na1W6UXrb9F8IEyNFWXe2B0y7Kqn?usp=sharing) and put in firebase folder

### Running the Server

To start the server, use the following command:

```bash
npm run dev
```

### Server Configuration

- **Port:** The server will run on port **8080**.
- **Base URL for Frontend:**
  ```
  http://localhost:8080
  ```

### Usage

After starting the server, open your browser and go to:

```
http://localhost:8080
```

### Troubleshooting

If the server fails to start, ensure no other process is using port 8080. You can change the port by modifying the server configuration file if needed.
