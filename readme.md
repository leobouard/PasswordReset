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

The script will automatically adapt to your Default Domain password policy and Fine-grained password policies. However, The minimum value of the slider for password length cannot be lower than 8, even if your password policy allows it. The maximum length available for password generation will be: minimum length + 16 characters.

For example, if your password policy is set to 12 characters minimum, the minimum value will be 12 and the maximum value will be 28 (12+16).

**Reminder**: Authenticated Users do not have access to fine-grained password policies by default. [How to display fine-grained password policy settings to Authenticated Users? - Synergix Support](https://synergixdesk.zendesk.com/hc/en-us/articles/202927708-How-to-display-fine-grained-password-policy-settings-to-Authenticated-Users-).

## About colors

Colors can be customized using the script parameters:

- `-PrimaryColor` will be used for the main buttons (search, cancel and reset) and the progress bar to show password lifetime.
- `-SecondaryColor` will be used for the clear button and borders.
- `-DarkColor` will be used for the baner and the password buttons (regen and copy to clipboard).
- `-AccentBGColor` will be used for the background of the password box and expander.

Parameter | Default value | Text color
--------- | ------------- | ----------
PrimaryColor | | White
SecondaryColor | #D5DFE5 | None
DarkColor | #2D3142 | White
AccentBGColor | #F2F2F2 | Black

## Other mentions

SVG icons comes from <https://fontawesome.com>.

Thank you to:

- [@Krysten LE LUEL](https://www.linkedin.com/in/krysten-le-luel-2348a9220/) for testing and proof-reading
- [@Glen REBILLARD](https://www.linkedin.com/in/glen-rebillard-ab89a854/) for the tip to stop depending on WinForm for message boxes.
