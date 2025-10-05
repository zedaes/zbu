use iced::widget::{button, text_input, Button, Column, Container, ProgressBar, Text, TextInput};
use iced::{theme, Alignment, Application, Command, Element, Length};
use rfd::FileDialog;

use iced::executor;

#[derive(Debug, Clone)]
enum Message {
    SourceChanged(String),
    BackupDirChanged(String),
    PasswordChanged(String),
    EncryptPressed,
    DecryptPressed,
    ProgressUpdated(u8),
    SelectSource,
    SelectBackupDir,
    // Commented out as it is not used
    OperationFinished(Result<(), String>),
}

struct BackupApp {
    source: String,
    backup_dir: String,
    password: String,
    _encrypt_button: button::State,
    _decrypt_button: button::State,
    _source_input: text_input::State,
    _backup_dir_input: text_input::State,
    _password_input: text_input::State,
    progress: f32,
    running: bool,
    status_message: String,
}

impl Application for BackupApp {
    type Theme = iced::theme::Theme;
    type Executor = executor::Default;
    type Message = Message;
    type Flags = ();

    fn new(_flags: ()) -> (BackupApp, Command<Message>) {
        (
            BackupApp {
                source: String::new(),
                backup_dir: String::new(),
                password: String::new(),
                _encrypt_button: button::State::new(),
                _decrypt_button: button::State::new(),
                _source_input: text_input::State::new(),
                _backup_dir_input: text_input::State::new(),
                _password_input: text_input::State::new(),
                progress: 0.0,
                running: false,
                status_message: String::new(),
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("ZBU Backup Tool")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::SourceChanged(val) => self.source = val,
            Message::BackupDirChanged(val) => self.backup_dir = val,
            Message::PasswordChanged(val) => self.password = val,
            Message::EncryptPressed => {
                if !self.running {
                    self.progress = 0.0;
                    self.running = true;
                    self.status_message = "Encrypting...".into();
                    return Command::perform(
                        encryption_task(
                            self.source.clone(),
                            self.backup_dir.clone(),
                            self.password.clone(),
                            |progress| {
                                Message::ProgressUpdated(progress as u8);
                            },
                        ),
                        |result| match result {
                            Ok(_) => Message::OperationFinished(Ok(())),
                            Err(e) => Message::OperationFinished(Err(e)),
                        },
                    );
                }
            }
            Message::SelectSource => {
                if let Some(path) = FileDialog::new().pick_file() {
                    self.source = path.display().to_string();
                }
            }
            Message::SelectBackupDir => {
                if let Some(path) = FileDialog::new().pick_folder() {
                    self.backup_dir = path.display().to_string();
                }
            }
            Message::DecryptPressed => {
                if !self.running {
                    self.progress = 0.0;
                    self.running = true;
                    self.status_message = "Decrypting...".into();
                    return Command::perform(
                        decryption_task(
                            self.source.clone(),
                            self.backup_dir.clone(),
                            self.password.clone(),
                        ),
                        |result| match result {
                            Ok(_) => Message::OperationFinished(Ok(())),
                            Err(e) => Message::OperationFinished(Err(e)),
                        },
                    );
                }
            }
            Message::ProgressUpdated(p) => {
                println!(
                    "Debug: p (u8) = {}, self.progress (before) = {}",
                    p, self.progress
                );
                self.progress = p as f32;
                println!("Debug: self.progress (after) = {}", self.progress);
            }
            Message::OperationFinished(result) => {
                self.running = false;
                match result {
                    Ok(_) => self.status_message = "Operation completed successfully.".into(),
                    Err(e) => self.status_message = format!("Error: {}", e),
                }
                self.progress = 0.0;
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let source_input = Button::new(Text::new("Select Source"))
            .padding(10)
            .on_press(Message::SelectSource);

        let backup_dir_input = Button::new(Text::new("Select Backup Directory"))
            .padding(10)
            .on_press(Message::SelectBackupDir);

        let progress_bar: ProgressBar<iced::Renderer> = ProgressBar::new(0.0..=1.0, self.progress);

        let save_location = Text::new(&self.status_message).size(16);

        let password_input = TextInput::new("Password", &self.password)
            .on_input(Message::PasswordChanged)
            .padding(10)
            .size(20);

        let encrypt_button = Button::new(Text::new("Encrypt"))
            .padding(10)
            .on_press(Message::EncryptPressed);

        let decrypt_button = Button::new(Text::new("Decrypt"))
            .padding(10)
            .on_press(Message::DecryptPressed);

        let progress_bar = ProgressBar::new(0.0..=1.0, self.progress);

        let content = Column::new()
            .padding(20)
            .align_items(Alignment::Center)
            .spacing(10)
            .push(source_input)
            .push(backup_dir_input)
            .push(password_input)
            .push(encrypt_button)
            .push(decrypt_button)
            .push(progress_bar)
            .push(save_location);

        Container::new(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
}

// Dummy async encryption function - replace with actual encrypt logic and progress reporting
async fn encryption_task(
    _source: String,
    _backup_dir: String,
    _password: String,
    progress_callback: impl Fn(f32) + Send + 'static,
) -> Result<(), String> {
    for i in 0..=100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        progress_callback(i as f32 / 100.0);
    }
    Ok(())
}

// Dummy async decryption function - replace with actual decrypt logic and progress reporting
async fn decryption_task(
    _backup_file: String,
    _output_dir: String,
    _password: String,
) -> Result<(), String> {
    // Simulate decryption and progress for demo
    for i in 0..=100 {
        let _ = iced::futures::future::ready(()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Emit progress messages to the GUI
        iced::futures::executor::block_on(async {
            Message::ProgressUpdated(i as u8);
        });
    }
    Ok(())
}

fn main() -> iced::Result {
    BackupApp::run(iced::Settings::default())
}
