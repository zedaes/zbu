use clap::{Parser, Subcommand};

mod decrypt;
mod encrypt;

use decrypt::run_decrypt;
use encrypt::run_encrypt;

#[cfg(feature = "gui")]
use iced::widget::{Button, Column, Container, Row, Text, TextInput};
#[cfg(feature = "gui")]
use iced::{Application, Command, Element, Length, Theme};
#[cfg(feature = "gui")]
use rfd::FileDialog;

#[derive(Parser)]
#[command(name = "zbu")]
#[command(about = "A secure backup utility with encryption", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long, help = "Source file or directory to backup")]
        source: String,
        
        #[arg(short, long, help = "Directory to save the encrypted backup")]
        backup_dir: String,
        
        #[arg(short, long, help = "Password for encryption")]
        password: String,
    },
    Decrypt {
        #[arg(short, long, help = "Backup file to decrypt")]
        backup_file: String,
        
        #[arg(short, long, help = "Output directory for restored files")]
        output_dir: String,
        
        #[arg(short, long, help = "Password for decryption")]
        password: String,
    },
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone)]
enum Message {
    SourceChanged(String),
    BackupDirChanged(String),
    PasswordChanged(String),
    ConfirmPasswordChanged(String),
    EncryptPressed,
    DecryptPressed,
    SelectSource,
    SelectBackupDir,
    OperationFinished(Result<String, String>),
}

#[cfg(feature = "gui")]
#[derive(Debug, Clone, Copy, PartialEq)]
enum OperationMode {
    Encrypt,
    Decrypt,
}

#[cfg(feature = "gui")]
struct BackupApp {
    source: String,
    backup_dir: String,
    password: String,
    confirm_password: String,
    running: bool,
    status_message: String,
    is_error: bool,
    mode: OperationMode,
}

#[cfg(feature = "gui")]
impl Application for BackupApp {
    type Theme = Theme;
    type Executor = iced::executor::Default;
    type Message = Message;
    type Flags = ();

    fn new(_flags: ()) -> (BackupApp, Command<Message>) {
        (
            BackupApp {
                source: String::new(),
                backup_dir: String::new(),
                password: String::new(),
                confirm_password: String::new(),
                running: false,
                status_message: String::new(),
                is_error: false,
                mode: OperationMode::Encrypt,
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("ZBU")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::SourceChanged(val) => {
                self.source = val;
                self.is_error = false;
            }
            Message::BackupDirChanged(val) => {
                self.backup_dir = val;
                self.is_error = false;
            }
            Message::PasswordChanged(val) => {
                self.password = val;
                self.is_error = false;
            }
            Message::ConfirmPasswordChanged(val) => {
                self.confirm_password = val;
                self.is_error = false;
            }
            Message::EncryptPressed => {
                if !self.running {
                    if self.source.is_empty() {
                        self.status_message = "Please select a source file or folder".into();
                        self.is_error = true;
                        return Command::none();
                    }
                    if self.backup_dir.is_empty() {
                        self.status_message = "Please select a backup directory".into();
                        self.is_error = true;
                        return Command::none();
                    }
                    if self.password.is_empty() {
                        self.status_message = "Please enter a password".into();
                        self.is_error = true;
                        return Command::none();
                    }
                    if self.password.len() < 8 {
                        self.status_message = "Password must be at least 8 characters".into();
                        self.is_error = true;
                        return Command::none();
                    }
                    if self.password != self.confirm_password {
                        self.status_message = "Passwords do not match".into();
                        self.is_error = true;
                        return Command::none();
                    }

                    self.running = true;
                    self.mode = OperationMode::Encrypt;
                    self.status_message = "Encrypting and backing up...".into();
                    self.is_error = false;

                    let source = self.source.clone();
                    let backup_dir = self.backup_dir.clone();
                    let password = self.password.clone();

                    return Command::perform(
                        async move { encryption_task(source, backup_dir, password).await },
                        Message::OperationFinished,
                    );
                }
            }
            Message::SelectSource => {
                let mode = self.mode;
                return Command::perform(
                    async move {
                        if mode == OperationMode::Encrypt {
                            if let Some(path) = FileDialog::new().pick_folder() {
                                return Some(path);
                            }
                            FileDialog::new().pick_file()
                        } else {
                            FileDialog::new()
                                .add_filter("Backup Files", &["backup"])
                                .pick_file()
                        }
                    },
                    |result| match result {
                        Some(path) => Message::SourceChanged(path.to_string_lossy().to_string()),
                        None => Message::SourceChanged(String::new()),
                    },
                );
            }
            Message::SelectBackupDir => {
                return Command::perform(
                    async { FileDialog::new().pick_folder() },
                    |result| match result {
                        Some(path) => Message::BackupDirChanged(path.to_string_lossy().to_string()),
                        None => Message::BackupDirChanged(String::new()),
                    },
                );
            }
            Message::DecryptPressed => {
                if !self.running {
                    if self.source.is_empty() {
                        self.status_message = "Please select a backup file to decrypt".into();
                        self.is_error = true;
                        return Command::none();
                    }
                    if self.backup_dir.is_empty() {
                        self.status_message = "Please select an output directory".into();
                        self.is_error = true;
                        return Command::none();
                    }
                    if self.password.is_empty() {
                        self.status_message = "Please enter the password".into();
                        self.is_error = true;
                        return Command::none();
                    }

                    self.running = true;
                    self.mode = OperationMode::Decrypt;
                    self.status_message = "Decrypting and restoring...".into();
                    self.is_error = false;

                    let source = self.source.clone();
                    let backup_dir = self.backup_dir.clone();
                    let password = self.password.clone();

                    return Command::perform(
                        async move { decryption_task(source, backup_dir, password).await },
                        Message::OperationFinished,
                    );
                }
            }
            Message::OperationFinished(result) => {
                self.running = false;
                match result {
                    Ok(msg) => {
                        self.status_message = msg;
                        self.is_error = false;
                    }
                    Err(e) => {
                        self.status_message = format!("Error: {}", e);
                        self.is_error = true;
                    }
                }
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let title = Text::new("ZBU - Secure Backup Utility")
            .size(32)
            .style(iced::theme::Text::Color(iced::Color::from_rgb(0.2, 0.4, 0.8)));

        let source_label = Text::new(if self.mode == OperationMode::Encrypt {
            "Source (File/Folder):"
        } else {
            "Backup File:"
        })
        .size(16);

        let source_display = Text::new(if self.source.is_empty() {
            "No source selected".to_string()
        } else {
            PathBuf::from(&self.source)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| self.source.clone())
        })
        .size(14)
        .style(iced::theme::Text::Color(iced::Color::from_rgb(0.4, 0.4, 0.4)));

        let source_button = Button::new(
            Text::new("Select Source")
                .horizontal_alignment(iced::alignment::Horizontal::Center),
        )
        .padding(12)
        .width(Length::Fill)
        .on_press_maybe(if !self.running {
            Some(Message::SelectSource)
        } else {
            None
        });

        let backup_label = Text::new(if self.mode == OperationMode::Encrypt {
            "Backup Directory:"
        } else {
            "Output Directory:"
        })
        .size(16);

        let backup_display = Text::new(if self.backup_dir.is_empty() {
            "No directory selected".to_string()
        } else {
            PathBuf::from(&self.backup_dir)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| self.backup_dir.clone())
        })
        .size(14)
        .style(iced::theme::Text::Color(iced::Color::from_rgb(0.4, 0.4, 0.4)));

        let backup_button = Button::new(
            Text::new("Select Directory")
                .horizontal_alignment(iced::alignment::Horizontal::Center),
        )
        .padding(12)
        .width(Length::Fill)
        .on_press_maybe(if !self.running {
            Some(Message::SelectBackupDir)
        } else {
            None
        });

        let password_input = TextInput::new("Enter password", &self.password)
            .on_input(Message::PasswordChanged)
            .padding(12)
            .size(16)
            .password()
            .width(Length::Fill);

        let confirm_password_input = TextInput::new("Confirm password", &self.confirm_password)
            .on_input(Message::ConfirmPasswordChanged)
            .padding(12)
            .size(16)
            .password()
            .width(Length::Fill);

        let password_section = if self.mode == OperationMode::Encrypt {
            Column::new()
                .spacing(8)
                .push(Text::new("Password:").size(16))
                .push(password_input)
                .push(confirm_password_input)
        } else {
            Column::new()
                .spacing(8)
                .push(Text::new("Password:").size(16))
                .push(password_input)
        };

        let encrypt_button = Button::new(
            Text::new("Encrypt & Backup")
                .horizontal_alignment(iced::alignment::Horizontal::Center),
        )
        .padding(15)
        .width(Length::Fill)
        .style(iced::theme::Button::Primary)
        .on_press_maybe(if !self.running {
            Some(Message::EncryptPressed)
        } else {
            None
        });

        let decrypt_button = Button::new(
            Text::new("Decrypt & Restore")
                .horizontal_alignment(iced::alignment::Horizontal::Center),
        )
        .padding(15)
        .width(Length::Fill)
        .style(iced::theme::Button::Secondary)
        .on_press_maybe(if !self.running {
            Some(Message::DecryptPressed)
        } else {
            None
        });

        let button_row = Row::new()
            .spacing(15)
            .push(encrypt_button)
            .push(decrypt_button);

        let mut content = Column::new()
            .padding(30)
            .spacing(20)
            .max_width(600)
            .push(title)
            .push(source_label)
            .push(source_display)
            .push(source_button)
            .push(backup_label)
            .push(backup_display)
            .push(backup_button)
            .push(password_section)
            .push(button_row);

        if !self.status_message.is_empty() {
            let status_color = if self.is_error {
                iced::Color::from_rgb(0.8, 0.2, 0.2)
            } else {
                iced::Color::from_rgb(0.2, 0.6, 0.3)
            };
            let status = Text::new(&self.status_message)
                .size(16)
                .style(iced::theme::Text::Color(status_color));
            content = content.push(status);
        }

        Container::new(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
}

#[cfg(feature = "gui")]
async fn encryption_task(
    source: String,
    backup_dir: String,
    password: String,
) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        run_encrypt(&source, &backup_dir, &password)
            .map(|_| format!("Successfully encrypted backup saved to: {}", backup_dir))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution error: {}", e))?
}

#[cfg(feature = "gui")]
async fn decryption_task(
    backup_file: String,
    output_dir: String,
    password: String,
) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        run_decrypt(&backup_file, &output_dir, &password)
            .map(|_| format!("Successfully restored backup to: {}", output_dir))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution error: {}", e))?
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Encrypt { source, backup_dir, password }) => {
            run_encrypt(&source, &backup_dir, &password)?;
            Ok(())
        }
        Some(Commands::Decrypt { backup_file, output_dir, password }) => {
            run_decrypt(&backup_file, &output_dir, &password)?;
            Ok(())
        }
        None => {
            #[cfg(feature = "gui")]
            {
                BackupApp::run(iced::Settings {
                    window: iced::window::Settings {
                        size: (500, 600),
                        resizable: false,
                        decorations: true,
                        ..Default::default()
                    },
                    antialiasing: false,
                    ..Default::default()
                })?;
                Ok(())
            }
            #[cfg(not(feature = "gui"))]
            {
                eprintln!("GUI feature not enabled. Use --help to see CLI options.");
                eprintln!("To use GUI, rebuild with: cargo build --features gui");
                std::process::exit(1);
            }
        }
    }
}
