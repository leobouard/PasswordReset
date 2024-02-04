# PasswordReset

A simple WPF interface for Active Directory user password reset.

![A preview of the UI](image.png)

This script requires the Active Directory module.

## About generated passwords

Password are automatically generated using the function `New-Password`. If the password is at least 4 characters long, then it will always contain a lowercase letter, an uppercase letter, a number and a special character.

To avoid confusion between certain characters, some letters and numbers are not used for password generation. This is the case for the following characters:

- Lower-case "L"
- Upper-case "I"
- Upper-case "O"
- Digit "0"

The list of special characters used is as follows: `! # $ % & * + - . / = ? @ _`.

### Password policies

The script will automatically adapt to your Default Domain password policy and Fine-grained password policies. However, The minimum value of the slider for password length cannot be lower than 10, even if your password policy allows it. The maximum length available for password generation will be: minimum length + 16 characters.

For example, if your password policy is set to 12 characters minimum, the minimum value will be 12 and the maximum value will be 28 (12+16).

**Reminder**: Authenticated Users do not have access to fine-grained password policies by default. [How to display fine-grained password policy settings to Authenticated Users? - Synergix Support](https://synergixdesk.zendesk.com/hc/en-us/articles/202927708-How-to-display-fine-grained-password-policy-settings-to-Authenticated-Users-).

## Parameters

### -ShowConsole

Invoke this parameter to prevent the script from hidding the console.

### -UseSecureRandom

Invoke this parameter to use a more secure way to get random items (using `Get-SecureRandom` or an equivalent). This method is slower than the standard method using `Get-Random`.

### -DateFormat

Modify the date format of the properties "Password last set" and "Last bad password attempt". You can use a .NET format specifier. Learn more here: [Custom date and time format strings
 \| Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/standard/base-types/custom-date-and-time-format-strings?view=netframework-4.8).

### -PrimaryColor

Color that will be used for the main buttons (search, cancel and reset) and the progress bar to show password lifetime.

## Other mentions

SVG icons comes from <https://fontawesome.com>.

Thank you to:

- [@Krysten LE LUEL](https://www.linkedin.com/in/krysten-le-luel-2348a9220/) for testing and proof-reading
- [@Glen REBILLARD](https://www.linkedin.com/in/glen-rebillard-ab89a854/) for the tip to stop depending on WinForm for message boxes.
