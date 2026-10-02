"""Prompt for local OAuth client settings and save them with .NET User Secrets."""

from __future__ import annotations

from getpass import getpass
import json
from pathlib import Path
import subprocess
import sys


PROJECT = Path(__file__).resolve().parents[1] / "Oauth2_backend.csproj"


def read_client(label: str) -> tuple[str, str]:
    client_id = input(f"{label} client ID: ").strip()
    client_secret = getpass(f"{label} client secret (input hidden): ").strip()
    if not client_id or not client_secret:
        raise ValueError(f"Both values are required for {label}.")
    return client_id, client_secret


def nested_settings(settings: dict[str, str]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in settings.items():
        path = key.split(":")
        current = result
        for segment in path[:-1]:
            child = current.setdefault(segment, {})
            if not isinstance(child, dict):
                raise ValueError(f"Conflicting configuration key: {key}")
            current = child
        current[path[-1]] = value
    return result


def save_settings(settings: dict[str, str]) -> None:
    result = subprocess.run(
        ["dotnet", "user-secrets", "set", "--project", str(PROJECT)],
        input=json.dumps(nested_settings(settings)),
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Could not save local settings. Check the .NET SDK and project path.")


def configure_provider_only(
    provider: str,
    label: str,
    callback_url: str,
) -> int:
    print(f"{label} OAuth setup")
    print("Values are saved to .NET User Secrets. The client secret is entered without echo.")

    client_id = input(f"{label} client ID: ").strip()
    if not client_id:
        print(f"{label} client ID is required.", file=sys.stderr)
        return 1

    client_secret = getpass(f"{label} client secret (input hidden): ").strip()
    if not client_secret:
        print(f"{label} client secret is required.", file=sys.stderr)
        return 1

    settings = {
        f"OAuth:{provider}:ClientId": client_id,
        f"OAuth:{provider}:ClientSecret": client_secret,
    }
    try:
        save_settings(settings)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        client_id = client_secret = ""
        settings.clear()

    print(f"\nSaved {label} OAuth settings in .NET User Secrets. Values were not displayed.")
    print("Register this callback URL:")
    print(f"  {label} profile:     {callback_url}")
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in ([], ["--github-only"], ["--discord-only"]):
        print("Usage: configure_local_oauth.py [--github-only|--discord-only]", file=sys.stderr)
        return 2
    if not PROJECT.is_file():
        print("Switchboard backend project was not found.", file=sys.stderr)
        return 1
    if not sys.stdin.isatty():
        print("Run this script from an interactive terminal so client secrets can be entered safely.", file=sys.stderr)
        return 1
    if arguments == ["--github-only"]:
        return configure_provider_only(
            "Github",
            "GitHub OAuth App",
            "http://localhost:5223/api/oauth/github/callback",
        )
    if arguments == ["--discord-only"]:
        return configure_provider_only(
            "Discord",
            "Discord application",
            "http://localhost:5223/api/oauth/discord/callback",
        )

    print("Local Switchboard OAuth setup")
    print("Values are saved to .NET User Secrets. Client secrets are entered without echo.")
    print("Use the redirect URLs shown below when registering each OAuth client.\n")

    print("Google Web OAuth client for the separate Google profile connection:")
    google_id, google_secret = read_client("Google Web OAuth")

    print("\nGitHub OAuth App client (press Enter at client ID to skip GitHub for now):")
    github_id = input("GitHub OAuth App client ID: ").strip()
    github_secret = getpass("GitHub OAuth App client secret (input hidden): ").strip() if github_id else ""
    if github_id and not github_secret:
        print("GitHub client secret is required when a client ID is supplied.", file=sys.stderr)
        return 1

    print("\nDiscord application credentials (press Enter at client ID to skip Discord for now):")
    discord_id = input("Discord application client ID: ").strip()
    discord_secret = getpass("Discord application client secret (input hidden): ").strip() if discord_id else ""
    if discord_id and not discord_secret:
        print("Discord client secret is required when a client ID is supplied.", file=sys.stderr)
        return 1

    settings = {
        "OAuth:Google:ClientId": google_id,
        "OAuth:Google:ClientSecret": google_secret,
        "App:PublicOrigin": "http://localhost:5223",
        "App:FrontendOrigin": "http://localhost:4300",
        "App:ForceDemo": "false",
    }
    if github_id:
        settings["OAuth:Github:ClientId"] = github_id
        settings["OAuth:Github:ClientSecret"] = github_secret
    github_configured = bool(github_id)
    if discord_id:
        settings["OAuth:Discord:ClientId"] = discord_id
        settings["OAuth:Discord:ClientSecret"] = discord_secret

    try:
        save_settings(settings)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        google_id = google_secret = ""
        github_id = github_secret = ""
        discord_id = discord_secret = ""
        settings.clear()

    print("\nSaved local OAuth settings in .NET User Secrets. Values were not displayed.")
    print("Register these callback URLs:")
    print("  Google profile:     http://localhost:5223/api/oauth/google/callback")
    if github_configured:
        print("  GitHub profile:     http://localhost:5223/api/oauth/github/callback")
    print("  Discord profile:    http://localhost:5223/api/oauth/discord/callback")
    print("Start the backend and Angular dev server on ports 5223 and 4300 to test these callbacks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
