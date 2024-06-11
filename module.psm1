function Search-User {
    param([string]$SearchString)

    if (!$SearchString) { return }
    $Global:user = $null
    $users = Get-ADUser -Filter { ANR -eq $SearchString } -Properties *
    
    if (($users | Measure-Object).Count -gt 1) {
        $comboboxSearch.Items.Clear()
        $users | Sort-Object Name | Select-Object -First 5 | ForEach-Object { $comboboxSearch.AddChild($_.UserPrincipalName) }
        $comboboxSearch.IsEnabled = $true
        $comboboxSearch.IsDropDownOpen = $true
    }
    else {
        $Global:User = $users
    }
}

function Update-UI {

    # Password policy
    $userPasswordPolicy = Get-ADUserResultantPasswordPolicy -Identity $user
    if (!$userPasswordPolicy) { 
        $userPasswordPolicy = Get-ADDefaultDomainPasswordPolicy
    }

    # Search bar
    $textboxSearch.Text = $Global:User.DisplayName
    $textboxSearch.ToolTip = $Global:User.CanonicalName

    # Auto-generated tab
    $slider.Minimum = if ($userPasswordPolicy.MinPasswordLength -le 10) { 10 } else { $userPasswordPolicy.MinPasswordLength }
    $slider.Maximum = $slider.Minimum + 16
    $slider.Value = $slider.Minimum
    $textboxPwdPreview.Text = New-Password -Length $slider.Value

    # Manual tab
    $passwordBox.Password = $null
    $textboxPassword.Text = $null
    $textboxPassword.Visibility = 'Hidden'
    $buttonShowPwd.Visibility = 'Visible'
    $buttonHidePwd.Visibility = 'Hidden' 

    # Account option
    if ($User.LockedOut -eq $false) { $checkboxUnlock.IsEnabled = $false } else { $checkboxUnlock.IsEnabled = $true }
    if ($User.Enabled -eq $true) { $checkboxEnable.IsEnabled = $false } else { $checkboxEnable.IsEnabled = $true }
    $checkboxUnlock.IsChecked = $false
    $checkboxEnable.IsChecked = $false
    $checkboxChangePwd.IsChecked = $false

    # Password information
    if ($user.PasswordLastSet) {
        $passwordLastSet.Content = "$(Get-Date $user.PasswordLastSet -Format $Global:DateFormat)"
        $passwordLastSet.ToolTip = "$([int](New-TimeSpan -Start $user.PasswordLastSet).TotalDays) day(s) ago"
    }
    else {
        $passwordLastSet.Content = $null
        $passwordLastSet.ToolTip = $null
    }
    if ($user.lastBadPasswordAttempt) {
        $lastBadPasswordAttempt.Content = "$(Get-Date $user.lastBadPasswordAttempt -Format $Global:DateFormat)"
        $lastBadPasswordAttempt.ToolTip = "$([int](New-TimeSpan -Start $user.lastBadPasswordAttempt).TotalDays) day(s) ago"
    }
    else {
        $lastBadPasswordAttempt.Content = $null
        $lastBadPasswordAttempt.ToolTip = $null
    }
    if ($user.passwordNeverExpires -eq $true -or $userPasswordPolicy.MaxPasswordAge.TotalDays -eq 0) {
        $passwordLifetime.Minimum = 0
        $passwordLifetime.Maximum = 100
        $passwordLifetime.Value = 0
        $passwordLifetime.ToolTip = "Password not subject to expiration"
    }
    else {
        $passwordLifetime.Minimum = $userPasswordPolicy.MinPasswordAge.TotalDays
        $passwordLifetime.Maximum = $userPasswordPolicy.MaxPasswordAge.TotalDays
        $passwordLifetime.Value = [int]([int](New-TimeSpan -Start $user.PasswordLastSet).TotalDays)
        $passwordLifetime.ToolTip = "$($passwordLifetime.Maximum - $passwordLifetime.Value) day(s) before expiration"
    }
    $passwordExpired.Content = $user.passwordExpired
    $passwordNeverExpires.Content = $user.passwordNeverExpires
    $passwordPolicy.Content = if ($userPasswordPolicy.Name) { $userPasswordPolicy.Name } else { "Default Domain Password Policy" }
    $passwordPolicy.ToolTip = $userPasswordPolicy.DistinguishedName

    $null = $xamGUI.LayoutTransform
}

function Clear-UI {

    $global:User = $null

    # Search bar
    $textboxSearch.Text = $null
    $textboxSearch.ToolTip = $null

    # Auto-generated tab
    $slider.Minimum = 10
    $slider.Maximum = $slider.Minimum + 16
    $slider.Value = $slider.Minimum
    $textboxPwdPreview.Text = $null

    # Manual entry
    $passwordBox.Password = $null
    $textboxPassword.Text = $null
    $textboxPassword.Visibility = 'Hidden'
    $buttonShowPwd.Visibility = 'Visible'
    $buttonHidePwd.Visibility = 'Hidden'
    Update-PasswordCompliance

    # Account options
    $checkboxUnlock.IsEnabled = $true
    $checkboxUnlock.IsChecked = $false
    $checkboxEnable.IsEnabled = $true
    $checkboxEnable.IsChecked = $false
    $checkboxChangePwd.IsChecked = $false

    # Password information
    $passwordLastSet.Content = $null
    $passwordLastSet.ToolTip = $null
    $lastBadPasswordAttempt.Content = $null
    $lastBadPasswordAttempt.ToolTip = $null
    $passwordLifetime.Minimum = 0
    $passwordLifetime.Maximum = 100
    $passwordLifetime.Value = $passwordLifetime.Minimum
    $passwordLifetime.ToolTip = $null
    $passwordExpired.Content = $null
    $passwordNeverExpires.Content = $null
    $passwordPolicy.Content = $null
    $passwordPolicy.ToolTip = $null
    
}

function Get-RandomCustom {
    param(
        [Parameter(Mandatory)][System.Object[]]$InputObject,
        [int]$Count = 1
    )

    if ($Global:UseSecureRandom.IsPresent) {
        if (Get-Command 'Get-SecureRandom' -ErrorAction SilentlyContinue) {
            $InputObject | Get-SecureRandom -Count $count
        }
        else {
            $cryptGen = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $memory = [byte[]]@(0) * $Count
            $cryptGen.GetBytes($memory)
            $cryptGen.Dispose()
            0..($Count - 1) | ForEach-Object {
                $index = [int]($memory[$_] % $InputObject.Length)
                $InputObject[$index]
            }
        }
    }
    else {
        Get-Random -InputObject $InputObject -Count $Count
    }
}

function New-Password {
    param([int]$Length = 10)

    [string]$password = ''
    $low = 'abcdefghijkmnopqrstuvwxyz'.ToCharArray() 
    $upp = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray()
    $spe = '!#$%&*+-./=?@_'.ToCharArray()
    $num = 1..9
    $all = $low + $upp + $spe + $num

    # Get one character of every type
    'low', 'upp', 'spe', 'num' | ForEach-Object {
        $password += Get-RandomCustom (Get-Variable $_ -ValueOnly)
    }
    while ($password.Length -lt $Length) { $password += Get-RandomCustom $all }
    (Get-RandomCustom $password.ToCharArray() -Count $Length) -join ''
}

function Test-Complexity {
    param(
        [string]$String,
        [switch]$Detail
    ) 

    $test = [PSCustomObject]@{
        Lowercase = $String -cmatch '[a-z]'
        Uppercase = $String -cmatch '[A-Z]'
        Number    = $String -match '[\d]'
        Special   = $String -match '[\W_]'
    }

    if ($Detail.IsPresent) { $test } else { ($test.Lowercase + $test.Uppercase + $test.Special + $test.Number) -ge 3 }    
}

function Update-PasswordCompliance {
    param([string]$String)

    $complexity = Test-Complexity -String $String -Detail
    $pwdCompliance = ($String.Length -ge $slider.Minimum) -and ((Test-Complexity -String $String) -eq $true)

    # Password compliance
    if ($pwdCompliance -eq $true) {
        $borderCompliance.BorderBrush = 'Green'
    } else {
        $borderCompliance.BorderBrush = 'Transparent'
    }

    # Lowercase
    switch ($complexity.Lowercase) {
        $true  { $labelLowercase.BorderBrush = 'Green' ; $labelLowercase.Foreground = 'DarkGreen' }
        $false { $labelLowercase.BorderBrush = 'LightGray' ; $labelLowercase.Foreground = 'DarkGray' }
    }

    # Uppercase
    switch ($complexity.Uppercase) {
        $true  { $labelUppercase.BorderBrush = 'Green' ; $labelUppercase.Foreground = 'DarkGreen' }
        $false { $labelUppercase.BorderBrush = 'LightGray' ; $labelUppercase.Foreground = 'DarkGray' }
    }

    # Number
    switch ($complexity.Number) {
        $true  { $labelNumber.BorderBrush = 'Green' ; $labelNumber.Foreground = 'DarkGreen' }
        $false { $labelNumber.BorderBrush = 'LightGray' ; $labelNumber.Foreground = 'DarkGray' }
    }

    # Special
    switch ($complexity.Special) {
        $true  { $labelSpecial.BorderBrush = 'Green' ; $labelSpecial.Foreground = 'DarkGreen' }
        $false { $labelSpecial.BorderBrush = 'LightGray' ; $labelSpecial.Foreground = 'DarkGray' }
    }

    # Length
    switch ($String.Length -ge $slider.Minimum) {
        $true  { $labelLength.BorderBrush = 'Green' ; $labelLength.Foreground = 'DarkGreen' }
        $false { $labelLength.BorderBrush = 'LightGray' ; $labelLength.Foreground = 'DarkGray' }
    }
}

function Hide-Console {
    Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '
    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 0)
}