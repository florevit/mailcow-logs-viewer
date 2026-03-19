# Editing settings from the web UI

You can manage most application settings from the **Settings** tab in the web UI instead of (or in addition to) using environment variables.

## Enable the feature

Set in your `.env`:

```env
SETTINGS_EDIT_VIA_UI_ENABLED=true
```

Restart the application. The Settings tab will then show an **Edit configuration** section with a form and two actions:

- **Import from ENV to DB** – copies the current effective configuration (defaults + ENV) into the database so you can later remove ENV vars and manage everything from the UI.
- **Save changes** – saves the form values to the database.

## Priority order

Configuration is resolved in this order (later overrides earlier):

1. **Defaults** (from the application)
2. **ENV** (environment variables / `.env`)
3. **DB** (values stored via the web UI)

So: DB overrides ENV, and ENV overrides defaults. After you use **Import from ENV to DB**, you can remove or change ENV vars and the values in the DB will still apply.

## What can be edited

All settings are editable from the UI **except** database connection settings (`POSTGRES_*`). Those must stay in ENV.

Sensitive fields (passwords, API key, etc.) are shown as masked in the form. Leave the field empty to keep the current value; enter a new value only when you want to change it.

## Scheduler / intervals

Changes to **fetch interval**, **correlation check interval**, **DMARC IMAP interval**, and **scheduler workers** take effect immediately after you save. The application reschedules the relevant background jobs and updates the thread pool without requiring a restart.

## Disabling UI editing

Set `SETTINGS_EDIT_VIA_UI_ENABLED=false` (or remove it) and restart. The Edit configuration section will disappear and all configuration will again come only from ENV/defaults.
