#ifndef AppVersion
  #error AppVersion must be supplied by scripts/build_installer.py
#endif
#ifndef SourceDir
  #error SourceDir must be supplied by scripts/build_installer.py
#endif

[Setup]
AppId={{CBEFB4D5-3574-4FCF-A4A5-AC8648C3EAD2}
AppName=CodeShield
AppVersion={#AppVersion}
AppVerName=CodeShield {#AppVersion}
AppPublisher=CodeShield
DefaultDirName={autopf}\CodeShield
DefaultGroupName=CodeShield
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=CodeShield_Setup_{#AppVersion}
SetupIconFile=..\resources\app_icon.ico
UninstallDisplayIcon={app}\CodeShield.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加选项："; Flags: unchecked

[Files]
Source: "{#SourceDir}\CodeShield\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\demo_project\*"; DestDir: "{app}\demo_project"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\CodeShield"; Filename: "{app}\CodeShield.exe"; WorkingDir: "{app}"
Name: "{group}\卸载 CodeShield"; Filename: "{uninstallexe}"
Name: "{autodesktop}\CodeShield"; Filename: "{app}\CodeShield.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\CodeShield.exe"; Description: "启动 CodeShield"; Flags: nowait postinstall skipifsilent
