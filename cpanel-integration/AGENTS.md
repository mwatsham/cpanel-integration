# AGENTS.md

## Project Overview
- **Project:** CPanel Intergation— A skill that permits configuration
- **Target user:** Web Admins
- **My skill level:** expert
- **Stack:** Python

## Commands
- **Install:** [e.g. `npm install`, `pip install -r requirements.txt`]
- **Dev:** [e.g. `npm run dev`, `python manage.py runserver`]
- **Build:** [e.g. `npm run build`]
- **Test:** [e.g. `npm test`, `pytest`]
- **Lint:** [e.g. `npm run lint`, `ruff check .`]

## Do
- If developing a Skill follow the latest Agents Skills open standard specification (https://agentskills.io/specification) and structure the skill inline with this standard.
- Read existing code before modifying anything
- Match existing patterns, naming, and style
- Handle errors gracefully — no silent failures
- Keep changes small and scoped to what was asked
- Run dev/build after changes to verify nothing broke
- Ask clarifying questions before guessing

## Don't
- Install new dependencies without asking
- Delete or overwrite files without confirming
- Hardcode secrets, API keys, or credentials
- Rewrite working code unless explicitly asked
- Push, deploy, or force-push without permission
- Make changes outside the scope of the request

## When Stuck
- If a task is large, break it into steps and confirm the plan first
- If you can't fix an error in 2 attempts, stop and explain the issue

## Testing
- Run existing tests after any change
- Add at least one test for new features
- Never skip or delete tests to make things pass

## Git
- Before creating code ensure that the local git repo has been initialised
- Small, focused commits with descriptive messages
- Perform file staging and commits after every change
- Never force push

## Response Style
- always respond with clear & concise messages
- use plain English when explaining to the User
- avoid long sentences, complex words, or long paragraphs
