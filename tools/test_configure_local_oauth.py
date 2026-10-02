import json
import unittest
from unittest.mock import Mock, patch

import configure_local_oauth as setup


class ConfigureLocalOAuthTests(unittest.TestCase):
    @patch.object(setup.subprocess, "run")
    def test_secret_values_are_piped_to_user_secrets_instead_of_process_arguments(self, run):
        run.return_value.returncode = 0
        values = {"OAuth:Discord:ClientSecret": "private-test-secret"}

        setup.save_settings(values)

        command = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertNotIn("private-test-secret", command)
        self.assertEqual(command[:3], ["dotnet", "user-secrets", "set"])
        self.assertEqual(
            json.loads(options["input"]),
            {"OAuth": {"Discord": {"ClientSecret": "private-test-secret"}}},
        )
        self.assertTrue(options["text"])
        self.assertFalse(options["check"])
        self.assertEqual(options["stdout"], setup.subprocess.DEVNULL)
        self.assertEqual(options["stderr"], setup.subprocess.DEVNULL)

    @patch.object(setup.subprocess, "run")
    def test_failed_user_secrets_command_does_not_echo_values(self, run):
        run.return_value.returncode = 1

        with self.assertRaisesRegex(RuntimeError, "Could not save local settings") as error:
            setup.save_settings({"OAuth:Discord:ClientSecret": "private-test-secret"})

        self.assertNotIn("private-test-secret", str(error.exception))

    @patch("builtins.print")
    @patch.object(setup, "save_settings")
    @patch.object(setup.sys, "stdin", new=Mock(isatty=Mock(return_value=True)))
    @patch.object(setup, "PROJECT", new=Mock(is_file=Mock(return_value=True)))
    @patch.object(setup, "getpass", side_effect=["google-secret"])
    @patch("builtins.input", side_effect=["google-id", "", ""])
    def test_google_profile_setup_does_not_create_youtube_or_app_login_settings(
        self, _input, _getpass, save, output
    ):
        captured_settings = {}
        save.side_effect = lambda values: captured_settings.update(values.copy())
        result = setup.main([])

        self.assertEqual(result, 0)
        values = captured_settings
        self.assertEqual(values["OAuth:Google:ClientId"], "google-id")
        self.assertEqual(values["OAuth:Google:ClientSecret"], "google-secret")
        self.assertNotIn("OAuth:Github:ClientId", values)
        self.assertNotIn("OAuth:Discord:ClientId", values)
        displayed_text = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertNotIn("google-secret", displayed_text)
        self.assertNotIn("Authentication:Google", values)
        self.assertNotIn("/signin-google", displayed_text)
        self.assertIn("http://localhost:5223/api/oauth/google/callback", displayed_text)
        self.assertIn("http://localhost:5223/api/oauth/discord/callback", displayed_text)

    @patch("builtins.print")
    @patch.object(setup, "save_settings")
    @patch.object(setup.sys, "stdin", new=Mock(isatty=Mock(return_value=True)))
    @patch.object(setup, "PROJECT", new=Mock(is_file=Mock(return_value=True)))
    @patch.object(setup, "getpass", return_value="github-secret")
    @patch("builtins.input", return_value="github-id")
    def test_github_only_setup_preserves_other_provider_settings_and_hides_secret(
        self, read_client_id, _getpass, save, output
    ):
        captured_settings = {}
        save.side_effect = lambda values: captured_settings.update(values.copy())

        result = setup.main(["--github-only"])

        self.assertEqual(result, 0)
        self.assertEqual(
            captured_settings,
            {
                "OAuth:Github:ClientId": "github-id",
                "OAuth:Github:ClientSecret": "github-secret",
            },
        )
        read_client_id.assert_called_once_with("GitHub OAuth App client ID: ")
        displayed_text = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertNotIn("github-secret", displayed_text)
        self.assertIn("http://localhost:5223/api/oauth/github/callback", displayed_text)

    @patch("builtins.print")
    @patch.object(setup, "save_settings")
    @patch.object(setup.sys, "stdin", new=Mock(isatty=Mock(return_value=True)))
    @patch.object(setup, "PROJECT", new=Mock(is_file=Mock(return_value=True)))
    @patch.object(setup, "getpass", return_value="discord-secret")
    @patch("builtins.input", return_value="discord-id")
    def test_discord_only_setup_saves_local_app_credentials_without_echo(
        self, read_client_id, _getpass, save, output
    ):
        captured_settings = {}
        save.side_effect = lambda values: captured_settings.update(values.copy())

        result = setup.main(["--discord-only"])

        self.assertEqual(result, 0)
        self.assertEqual(
            captured_settings,
            {
                "OAuth:Discord:ClientId": "discord-id",
                "OAuth:Discord:ClientSecret": "discord-secret",
            },
        )
        read_client_id.assert_called_once_with("Discord application client ID: ")
        displayed_text = "\n".join(str(call.args[0]) for call in output.call_args_list)
        self.assertNotIn("discord-secret", displayed_text)
        self.assertIn("http://localhost:5223/api/oauth/discord/callback", displayed_text)


if __name__ == "__main__":
    unittest.main()
