function Search-User {
    param([string]$SearchString)

    if (!$SearchString) { return }
    $Global:user = $null
    $users = Get-ADUser -Filter {ANR -eq $SearchString} -Properties *
    
    if (($users | Measure-Object).Count -gt 1) {
        $comboboxSearch.Items.Clear()
        $users | Sort-Object Name | Select-Object -First 5 | ForEach-Object { $comboboxSearch.AddChild($_.UserPrincipalName) }
        $comboboxSearch.IsEnabled = $true
        $comboboxSearch.IsDropDownOpen = $true
    } else {
        $Global:User = $users
    }
}

function Update-UI {

    $textboxSearch.Text = $Global:User.DisplayName
    $textboxSearch.ToolTip = $Global:User.CanonicalName

    if ($User.LockedOut -eq $false) { $checkboxUnlock.IsEnabled = $false } else { $checkboxUnlock.IsEnabled = $true }
    if ($User.Enabled -eq $true) { $checkboxEnable.IsEnabled = $false } else { $checkboxEnable.IsEnabled = $true }

    $checkboxUnlock.IsChecked = $false
    $checkboxEnable.IsChecked = $false
    $checkboxChangePwd.IsChecked = $false

    $userPasswordPolicy = Get-ADUserResultantPasswordPolicy -Identity $user
    if (!$userPasswordPolicy) { $userPasswordPolicy = Get-ADDefaultDomainPasswordPolicy }

    if ($user.PasswordLastSet) {
        $passwordLastSet.Content = "$(Get-Date $user.PasswordLastSet -Format $Global:DateFormat)"
        $passwordLastSet.ToolTip = "$([int](New-TimeSpan -Start $user.PasswordLastSet).TotalDays) day(s) ago"
    } else {
        $passwordLastSet.Content = $null
        $passwordLastSet.ToolTip = $null
    }

    if ($user.lastBadPasswordAttempt) {
        $lastBadPasswordAttempt.Content = "$(Get-Date $user.lastBadPasswordAttempt -Format $Global:DateFormat)"
        $lastBadPasswordAttempt.ToolTip = "$([int](New-TimeSpan -Start $user.lastBadPasswordAttempt).TotalDays) day(s) ago"
    } else {
        $lastBadPasswordAttempt.Content = $null
        $lastBadPasswordAttempt.ToolTip = $null
    }

    $slider.Minimum = if ($userPasswordPolicy.MinPasswordLength -le 8) { 8 } else { $userPasswordPolicy.MinPasswordLength }
    $slider.Maximum = $slider.Minimum + 16
    $slider.Value   = $slider.Minimum

    $labelPwdPreview.Content = New-Password -Length $slider.Value
    $labelPwdPreview.ToolTip = $labelPwdPreview.Content

    if ($user.passwordNeverExpires -eq $true -or $userPasswordPolicy.MaxPasswordAge.TotalDays -eq 0) {
        $passwordLifetime.Minimum = 0
        $passwordLifetime.Maximum = 100
        $passwordLifetime.Value   = 0
        $passwordLifetime.ToolTip = "Password not subject to expiration"
    } else {
        $passwordLifetime.Minimum = $userPasswordPolicy.MinPasswordAge.TotalDays
        $passwordLifetime.Maximum = $userPasswordPolicy.MaxPasswordAge.TotalDays
        $passwordLifetime.Value   = [int]([int](New-TimeSpan -Start $user.PasswordLastSet).TotalDays)
        $passwordLifetime.ToolTip = "$($passwordLifetime.Maximum - $passwordLifetime.Value) day(s) before expiration"
    }
    
    $passwordExpired.Content = $user.passwordExpired
    $passwordNeverExpires.Content = $user.passwordNeverExpires
    $passwordPolicy.Content = if ($userPasswordPolicy.Name) { $userPasswordPolicy.Name } else { "Default Domain Password Policy" }
    $passwordPolicy.ToolTip = $userPasswordPolicy.DistinguishedName

    $null = $xamGUI.LayoutTransform
}

function Clear-UI {
    $global:User                    = $null
    $textboxSearch.Text             = $null
    $textboxSearch.ToolTip          = $null
    $checkboxUnlock.IsEnabled       = $true
    $checkboxUnlock.IsChecked       = $false
    $checkboxEnable.IsEnabled       = $true
    $checkboxEnable.IsChecked       = $false
    $checkboxChangePwd.IsChecked    = $false
    $passwordLastSet.Content        = $null
    $passwordLastSet.ToolTip        = $null
    $lastBadPasswordAttempt.Content = $null
    $lastBadPasswordAttempt.ToolTip = $null
    $slider.Minimum                 = 10
    $slider.Maximum                 = $slider.Minimum + 16
    $slider.Value                   = $slider.Minimum
    $labelPwdPreview.Content        = $null
    $labelPwdPreview.ToolTip        = $null
    $passwordLifetime.Minimum       = 0
    $passwordLifetime.Maximum       = 100
    $passwordLifetime.Value         = $passwordLifetime.Minimum
    $passwordLifetime.ToolTip       = $null
    $passwordExpired.Content        = $null
    $passwordNeverExpires.Content   = $null
    $passwordPolicy.Content         = $null
    $passwordPolicy.ToolTip         = $null
    # $window.Height                = $window.MinHeight
    # $expander.IsExpanded          = $false

    # $null = $xamGUI.LayoutTransform
}

function Get-RandomCustom {
    param(
        [Parameter(Mandatory)][System.Object[]]$InputObject,
        [int]$Count = 1
    )

    if ($Global:UseSecureRandom.IsPresent) {
        if (Get-Command 'Get-SecureRandom' -ErrorAction SilentlyContinue) {
            $InputObject | Get-SecureRandom -Count $count
        } else {
            $cryptGen = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $memory   = [byte[]]@(0)*$Count
            $cryptGen.GetBytes($memory)
            $cryptGen.Dispose()
            0..($Count-1) | ForEach-Object {
                $index = [int]($memory[$_]%$InputObject.Length)
                $InputObject[$index]
            }
        }
    } else {
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

    'low','upp','spe','num' | ForEach-Object { Invoke-Expression -Command "`$password += Get-RandomCustom `$$_" }
    while ($password.Length -lt $Length) { $password += Get-RandomCustom $all }
    (Get-RandomCustom $password.ToCharArray() -Count $Length) -join ''
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