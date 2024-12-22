[Setup]
AppName=Dela Tool
AppVersion=1.0
DefaultDirName={commonpf}\Dela Tools
DisableDirPage=no
DefaultGroupName=Dela Tool
OutputBaseFilename=DelaToolSetup
Compression=lzma
SolidCompression=yes


[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional Icons:"; Flags: unchecked


[Files]
Source: "agent.exe"; DestDir: "{app}"; Flags: ignoreversion; Check: ShouldInstallAgent
Source: "agent_runner.py"; DestDir: "{app}"; Flags: ignoreversion; Check: ShouldInstallAgent
Source: "python_tool.exe"; DestDir: "{app}"; Flags: ignoreversion; Check: ShouldInstallPythonTool
Source: ".\DC\*.ps1"; DestDir: "{app}\DC"; Flags: ignoreversion; Check: ShouldInstallPythonTool

[Icons]
Name: "{commondesktop}\Dela Tool Agent"; Filename: "{app}\agent.exe"; Tasks: desktopicon
Name: "{group}\Dela Tool Agent"; Filename: "{app}\agent.exe"

[INI]
Filename: "{app}\config.ini"; Section: "AWS"; Key: "Username"; String: "{code:GetAWSUsername}"
Filename: "{app}\config.ini"; Section: "AWS"; Key: "Password"; String: "{code:GetEncryptedAWSPassword}"
Filename: "{app}\config.ini"; Section: "PythonTool"; Key: "Port"; String: "{code:GetPythonToolPort}"

[Run]
; For InstallationChoice = 1 (Dela Tool and Agent)
Filename: "cmd"; Parameters: "/C python agent_runner.py install && python agent_runner.py start"; WorkingDir: "{app}"; Flags: postinstall skipifsilent; Description: "Install agent as a Windows service and run agent";Check: ShouldRunAgent
Filename: "{app}\python_tool.exe"; Flags: postinstall skipifsilent; Check: ShouldRunPythonTool


[Code]
var
  AWSUsernameEdit: TEdit;
  AWSPasswordEdit: TEdit;
  PythonToolPortEdit: TEdit;
  DomainControllerCheckBox: TCheckBox;

  AWSUsername: string;
  AWSPassword: string;
  PythonToolPort: string;
  HasDomainController: Boolean;

  InstallOptionPage: TWizardPage;
  DelaToolAndAgentRadioButton: TRadioButton;
  InstallAgentRadioButton: TRadioButton;
  InstallDelaToolRadioButton: TRadioButton;
  InstallationChoice: Integer; // 1 = Dela Tool and Agent, 2 = Agent only, 3 = Dela Tool only

function Base64Encode(const Input: string): string;
var
  I, J: Integer;
  A, B, C: Byte;
  Output: string;
  Base64Table: string;
begin
  Output := '';
  Base64Table := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  I := 1;
  while I <= Length(Input) do
  begin
    A := Ord(Input[I]);
    Inc(I);
    if I <= Length(Input) then
      B := Ord(Input[I])
    else
      B := 0;
    Inc(I);
    if I <= Length(Input) then
      C := Ord(Input[I])
    else
      C := 0;
    Inc(I);

    Output := Output + Base64Table[(A shr 2) + 1];
    Output := Output + Base64Table[((A and $03) shl 4) or (B shr 4) + 1];
    if I - 2 <= Length(Input) then
      Output := Output + Base64Table[((B and $0F) shl 2) or (C shr 6) + 1]
    else
      Output := Output + '=';
    if I - 1 <= Length(Input) then
      Output := Output + Base64Table[C and $3F + 1]
    else
      Output := Output + '=';
  end;
  Result := Output;
end;

function EncryptPassword(Pass: string): string;
begin
  Result := Base64Encode(Pass);
end;

function IsValidPort(Port: string): Boolean;
var
  ColonPos: Integer;
  IP, PortNumber: string;
begin
  ColonPos := Pos(':', Port);
  if ColonPos > 0 then
  begin
    IP := Copy(Port, 1, ColonPos - 1);
    PortNumber := Copy(Port, ColonPos + 1, Length(Port) - ColonPos);
    Result := (Length(IP) > 0) and (Length(PortNumber) > 0);
  end
  else
    Result := False;
end;


procedure OnInstallAgentRadioButtonClick(Sender: TObject);
begin
  InstallationChoice := 1;
end;

procedure OnInstallDelaToolRadioButtonClick(Sender: TObject);
begin
  InstallationChoice := 2;
end;

procedure InitializeWizard();
var
  InputPage: TWizardPage;
  AWSUsernameLabel, AWSPasswordLabel, PythonToolPortLabel: TLabel;
begin
  AWSUsername := '';
  AWSPassword := '';
  PythonToolPort := '';
  InstallationChoice := 1;
  
  // Create Installation Options Page
  InstallOptionPage := CreateCustomPage(wpSelectDir + 1, 'Installation Type', 'Choose which components to install.');

  InstallAgentRadioButton := TRadioButton.Create(InstallOptionPage.Surface);
InstallAgentRadioButton.Parent := InstallOptionPage.Surface;
InstallAgentRadioButton.Caption := '"Install Dela Proxy Only"';
InstallAgentRadioButton.Left := 20;
InstallAgentRadioButton.Top := 10;
InstallAgentRadioButton.Checked := True;
InstallAgentRadioButton.Width := InstallOptionPage.SurfaceWidth - 40;
InstallAgentRadioButton.Height := 25;
InstallAgentRadioButton.OnClick := @OnInstallAgentRadioButtonClick;

InstallDelaToolRadioButton := TRadioButton.Create(InstallOptionPage.Surface);
InstallDelaToolRadioButton.Parent := InstallOptionPage.Surface;
InstallDelaToolRadioButton.Caption := '"Install Dela Tool Only"';
InstallDelaToolRadioButton.Left := 20;
InstallDelaToolRadioButton.Top := InstallAgentRadioButton.Top + InstallAgentRadioButton.Height + 100; 
InstallDelaToolRadioButton.Width := InstallOptionPage.SurfaceWidth - 40;
InstallDelaToolRadioButton.Height := 25;
InstallDelaToolRadioButton.OnClick := @OnInstallDelaToolRadioButtonClick;

with TLabel.Create(InstallOptionPage.Surface) do
begin
  Parent := InstallOptionPage.Surface;
  Caption := 'Dela Proxy is a program that runs as a service, connecting to the Dela tool on';
  Left := 40;
  Top := InstallAgentRadioButton.Top + InstallAgentRadioButton.Height + 5;
  Width := InstallOptionPage.SurfaceWidth - 80;  
  Font.Color := clGray;
end;

with TLabel.Create(InstallOptionPage.Surface) do
begin
  Parent := InstallOptionPage.Surface;
  Caption := 'a different domain controller.';
  Left := 40;
  Top := InstallAgentRadioButton.Top + InstallAgentRadioButton.Height + 30; 
  Width := InstallOptionPage.SurfaceWidth - 80;  
  Font.Color := clGray;
end;

with TLabel.Create(InstallOptionPage.Surface) do
begin
  Parent := InstallOptionPage.Surface;
  Caption := 'Only the Dela Tool will be installed and run on this machine. It will capture ';
  Left := 40;
  Top := InstallDelaToolRadioButton.Top + InstallDelaToolRadioButton.Height + 5;
  Width := InstallOptionPage.SurfaceWidth - 80; 
  Font.Color := clGray;
end;

with TLabel.Create(InstallOptionPage.Surface) do
begin
  Parent := InstallOptionPage.Surface;
  Caption := 'domain controller information and send the results to the Dela Proxy.';
  Left := 40;
  Top := InstallDelaToolRadioButton.Top + InstallDelaToolRadioButton.Height + 30; // Adjusted spacing
  Width := InstallOptionPage.SurfaceWidth - 80;  // Adjusted width
  Font.Color := clGray;
end;




  // Create AWS Credentials Page
  InputPage := CreateCustomPage(wpSelectDir + 2, 'AWS and Port Configuration', 'Enter your AWS credentials and tool configuration.');

  AWSUsernameLabel := TLabel.Create(InputPage.Surface);
  AWSUsernameLabel.Parent := InputPage.Surface;
  AWSUsernameLabel.Caption := 'Dela Username:';
  AWSUsernameLabel.Left := 10;
  AWSUsernameLabel.Top := 20;

  AWSUsernameEdit := TEdit.Create(InputPage.Surface);
  AWSUsernameEdit.Parent := InputPage.Surface;
  AWSUsernameEdit.Left := 10;
  AWSUsernameEdit.Top := 40;
  AWSUsernameEdit.Width := InputPage.SurfaceWidth - 20;

  AWSPasswordLabel := TLabel.Create(InputPage.Surface);
  AWSPasswordLabel.Parent := InputPage.Surface;
  AWSPasswordLabel.Caption := 'Dela Password:';
  AWSPasswordLabel.Left := 10;
  AWSPasswordLabel.Top := 80;

  AWSPasswordEdit := TEdit.Create(InputPage.Surface);
  AWSPasswordEdit.Parent := InputPage.Surface;
  AWSPasswordEdit.Left := 10;
  AWSPasswordEdit.Top := 100;
  AWSPasswordEdit.Width := AWSUsernameEdit.Width;
  AWSPasswordEdit.PasswordChar := '*';

end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;

  if CurPageID = 101 then
  begin
    AWSUsername := AWSUsernameEdit.Text;
    AWSPassword := AWSPasswordEdit.Text;
 
    if AWSUsername = '' then
    begin
      MsgBox('Username cannot be empty.', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    if AWSPassword = '' then
    begin
      MsgBox('Password cannot be empty.', mbError, MB_OK);
      Result := False;
      Exit;
    end;

  end;
end;

function ShouldInstallAgent: Boolean;
begin
  Result := (InstallationChoice = 1)
end;

function ShouldInstallPythonTool: Boolean;
begin
  Result := (InstallationChoice = 2);
end;

function ShouldRunAgent: Boolean;
begin
  Result := (InstallationChoice = 1)
end;

function ShouldRunPythonTool: Boolean;
begin
  Result := (InstallationChoice = 2);
end;


function GetAWSUsername(Param: string): string;
begin
  Result := AWSUsername;
end;

function GetEncryptedAWSPassword(Param: string): string;
begin
  Result := EncryptPassword(AWSPassword);
end;

function GetPythonToolPort(Param: string): string;
begin
  Result := PythonToolPort;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;

  if PageID = 101 then
  begin
    if InstallationChoice = 2 then
    begin
      Result := True;
    end;
  end;
end;