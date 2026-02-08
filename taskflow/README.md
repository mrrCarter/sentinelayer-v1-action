# TaskFlow

> Modern task management for agile teams 🚀

TaskFlow is a full-stack task management application with Kanban boards, team collaboration, and Stripe-powered Pro subscriptions.

## Tech Stack

- **Backend:** Node.js, Express, PostgreSQL, Redis
- **Frontend:** React, Tailwind CSS
- **Payments:** Stripe
- **Deployment:** Docker, AWS ECS

## Quick Start

```bash
# Clone and install
git clone https://github.com/alexcodes/taskflow.git
cd taskflow
npm install

# Set up environment
cp .env.example .env
# Edit .env with your values

# Start with Docker
docker-compose up -d

# Run migrations
npm run migrate

# Start development server
npm run dev
```

## API Endpoints

### Auth
- `POST /api/auth/register` — Create account
- `POST /api/auth/login` — Login
- `POST /api/auth/refresh` — Refresh token
- `POST /api/auth/forgot-password` — Request password reset

### Tasks
- `GET /api/tasks` — List tasks (with filters)
- `GET /api/tasks/search?q=` — Search tasks
- `POST /api/tasks` — Create task
- `PUT /api/tasks/:id` — Update task
- `DELETE /api/tasks/:id` — Delete task

### Users
- `GET /api/users` — List team members
- `PUT /api/users/me` — Update profile
- `DELETE /api/users/me` — Delete account

### Admin
- `GET /api/admin/dashboard` — System metrics
- `GET /api/admin/users` — All users (admin only)

## Development

```bash
# Run tests
npm test

# Lint
npm run lint

# Build client
npm run build
```

## Project Structure

```
taskflow/
├── src/
│   ├── server/          # Express API
│   │   ├── config/      # Database & env config
│   │   ├── routes/      # API route handlers
│   │   ├── middleware/   # Auth, validation
│   │   ├── models/      # Database models
│   │   └── services/    # Business logic
│   └── client/          # React frontend
│       ├── src/
│       │   ├── components/
│       │   ├── pages/
│       │   └── utils/
│       └── public/
├── docker-compose.yml
└── package.json
```

## Contributing

1. Create a feature branch from `develop`
2. Make your changes
3. Open a PR against `develop`
4. CI will run tests + SentinelLayer security scan

## License

MIT © Alex Chen

