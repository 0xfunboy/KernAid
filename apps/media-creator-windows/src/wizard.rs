use crate::windows_backend::{
    AppError, CreatedMedia, LoadedRelease, WindowsDiskBackend, create_release_media,
    load_release_bundle,
};
use kernaid_media_creator_core::{
    DiskBackend, DiskCandidate, EligibleDisk, MediaPhase, MediaProgress, eligible_disks,
    select_disk,
};
use std::{
    ffi::{OsString, c_void},
    mem::size_of,
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    ptr::{null, null_mut},
    thread,
};
use windows_sys::Win32::{
    Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
    Graphics::Gdi::{COLOR_WINDOW, DEFAULT_GUI_FONT, GetStockObject, HBRUSH, UpdateWindow},
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        Controls::Dialogs::{
            CommDlgExtendedError, GetOpenFileNameW, OFN_DONTADDTORECENT, OFN_FILEMUSTEXIST,
            OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
        },
        Controls::{
            BST_CHECKED, ICC_PROGRESS_CLASS, INITCOMMONCONTROLSEX, InitCommonControlsEx,
            PBM_SETPOS, PBM_SETRANGE32, PBS_SMOOTH,
        },
        HiDpi::{
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForSystem,
            SetProcessDpiAwarenessContext,
        },
        Input::KeyboardAndMouse::{EnableWindow, SetFocus},
        WindowsAndMessaging::{
            BM_GETCHECK, BN_CLICKED, BS_AUTOCHECKBOX, BS_DEFPUSHBUTTON, BS_PUSHBUTTON,
            CB_ADDSTRING, CB_ERR, CB_GETCURSEL, CB_SETCURSEL, CBS_DROPDOWNLIST, CBS_HASSTRINGS,
            CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW,
            DestroyWindow, DispatchMessageW, ES_AUTOHSCROLL, ES_READONLY, GWLP_USERDATA,
            GetMessageW, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, IDC_ARROW,
            IDI_APPLICATION, IsDialogMessageW, LoadCursorW, LoadIconW, MB_ICONERROR,
            MB_ICONWARNING, MB_OK, MB_TASKMODAL, MSG, MessageBoxW, PostMessageW, PostQuitMessage,
            RegisterClassW, SW_SHOW, SendMessageW, SetWindowLongPtrW, SetWindowTextW, ShowWindow,
            TranslateMessage, WM_APP, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_NCCREATE, WM_NCDESTROY,
            WM_SETFONT, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN, WS_EX_APPWINDOW,
            WS_EX_CLIENTEDGE, WS_EX_CONTROLPARENT, WS_MINIMIZEBOX, WS_SYSMENU, WS_TABSTOP,
            WS_VISIBLE,
        },
    },
};

const CLASS_NAME: &str = "KernAidMediaCreatorWizard";
const WINDOW_TITLE: &str = "KernAid Media Creator";
const WINDOW_WIDTH: i32 = 780;
const WINDOW_HEIGHT: i32 = 560;

const ID_BROWSE: u16 = 1001;
const ID_BACK: u16 = 1002;
const ID_NEXT: u16 = 1003;
const ID_CANCEL: u16 = 1004;
const ID_REFRESH: u16 = 1005;
const ID_DISKS: u16 = 1006;
const ID_CONFIRM_CHECK: u16 = 1007;
const ID_CONFIRM_TEXT: u16 = 1008;
const ID_START: u16 = 1009;
const ID_RESTART: u16 = 1010;

const WM_WIZARD_PROGRESS: u32 = WM_APP + 1;
const WM_WIZARD_COMPLETE: u32 = WM_APP + 2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Image,
    Usb,
    Confirm,
    Progress,
    Complete,
}

struct ProgressUpdate {
    percent: u32,
    status: &'static str,
}

#[derive(Clone)]
enum Completion {
    Success(CreatedMedia),
    Failed(String),
}

struct Wizard {
    hwnd: HWND,
    instance: HINSTANCE,
    dpi: u32,
    controls: Vec<HWND>,
    screen: Screen,
    message: Option<String>,
    release: Option<LoadedRelease>,
    backend: Option<WindowsDiskBackend>,
    snapshot: Vec<DiskCandidate>,
    eligible: Vec<EligibleDisk>,
    selected_disk: Option<usize>,
    confirmation_phrase: Option<String>,
    running: bool,
    completion: Option<Completion>,
    disk_combo: HWND,
    confirmation_check: HWND,
    confirmation_text: HWND,
    progress_bar: HWND,
    progress_status: HWND,
    progress_detail: HWND,
}

impl Wizard {
    fn new(instance: HINSTANCE, dpi: u32) -> Self {
        Self {
            hwnd: null_mut(),
            instance,
            dpi,
            controls: Vec::new(),
            screen: Screen::Image,
            message: None,
            release: None,
            backend: None,
            snapshot: Vec::new(),
            eligible: Vec::new(),
            selected_disk: None,
            confirmation_phrase: None,
            running: false,
            completion: None,
            disk_combo: null_mut(),
            confirmation_check: null_mut(),
            confirmation_text: null_mut(),
            progress_bar: null_mut(),
            progress_status: null_mut(),
            progress_detail: null_mut(),
        }
    }

    fn scaled(&self, value: i32) -> i32 {
        value.saturating_mul(self.dpi as i32) / 96
    }

    fn render(&mut self) -> Result<(), AppError> {
        self.clear_controls();
        match self.screen {
            Screen::Image => self.render_image(),
            Screen::Usb => self.render_usb(),
            Screen::Confirm => self.render_confirm(),
            Screen::Progress => self.render_progress(),
            Screen::Complete => self.render_complete(),
        }
    }

    fn render_image(&mut self) -> Result<(), AppError> {
        self.render_heading(
            "Step 1 of 5",
            "Choose your KernAid release",
            "Select the one KernAid release-bundle manifest you downloaded. The app rejects mixed, modified, unsigned, or unqualified release files.",
        )?;
        let path = self
            .release
            .as_ref()
            .map(|release| release.manifest_path.to_string_lossy().into_owned())
            .unwrap_or_else(|| "No release bundle selected".to_owned());
        self.add_control(
            "EDIT",
            &path,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32 | ES_READONLY as u32,
            WS_EX_CLIENTEDGE,
            40,
            180,
            550,
            30,
            0,
        )?;
        let browse = self.add_button("&Browse...", 610, 180, 120, 30, ID_BROWSE, true)?;
        let status = match self.release.as_ref() {
            Some(release) => format!(
                "Authorized release: {}\r\nSignature, catalog, qualification, metadata, and image descriptor are bound to this exact bundle.",
                release.authorized.artifact_version()
            ),
            None => "Choose the file named KernAid-Rescue-amd64.media-bundle.json. Keep it in the release folder with the image and metadata files.".to_owned(),
        };
        self.add_control(
            "STATIC",
            &status,
            WS_CHILD | WS_VISIBLE,
            0,
            40,
            235,
            690,
            70,
            0,
        )?;
        self.render_message(320)?;
        let next = self.add_button("&Next", 610, 465, 120, 34, ID_NEXT, true)?;
        if self.release.is_none() {
            enable(next, false);
        }
        self.add_button("Cancel", 475, 465, 120, 34, ID_CANCEL, false)?;
        focus(browse);
        Ok(())
    }

    fn render_usb(&mut self) -> Result<(), AppError> {
        self.render_heading(
            "Step 2 of 5",
            "Choose the USB drive",
            "Only unambiguous whole removable USB drives are shown. Internal, boot, system, fixed, read-only, and undersized disks are never selectable.",
        )?;
        self.add_control(
            "STATIC",
            "Removable USB drive:",
            WS_CHILD | WS_VISIBLE,
            0,
            40,
            175,
            300,
            24,
            0,
        )?;
        let combo = self.add_control(
            "COMBOBOX",
            "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST as u32 | CBS_HASSTRINGS as u32,
            WS_EX_CLIENTEDGE,
            40,
            202,
            550,
            240,
            ID_DISKS,
        )?;
        self.disk_combo = combo;
        for disk in &self.eligible {
            let size_gb = disk.capacity_bytes / 1_000_000_000;
            let label = format!("{} — {} GB — serial {}", disk.model, size_gb, disk.serial);
            let label_wide = wide(&label);
            let result = unsafe {
                // SAFETY: combo is a live child window and label_wide remains valid for the call.
                SendMessageW(combo, CB_ADDSTRING, 0, label_wide.as_ptr() as LPARAM)
            };
            if result == CB_ERR as LRESULT {
                return Err(AppError::Message(
                    "the removable USB list could not be displayed".to_owned(),
                ));
            }
        }
        if !self.eligible.is_empty() {
            unsafe {
                // SAFETY: combo is live and index zero exists.
                SendMessageW(combo, CB_SETCURSEL, 0, 0);
            }
        }
        self.add_button("&Refresh", 610, 202, 120, 30, ID_REFRESH, false)?;
        if self.eligible.is_empty() {
            self.add_control(
                "STATIC",
                "No safe removable USB drive was found. Insert an empty 32 GB or larger USB drive, wait a few seconds, then choose Refresh.",
                WS_CHILD | WS_VISIBLE,
                0,
                40,
                265,
                690,
                60,
                0,
            )?;
        } else {
            self.add_control(
                "STATIC",
                "Tip: unplug any USB drive you do not want to erase. The selected drive is rechecked again immediately before raw access.",
                WS_CHILD | WS_VISIBLE,
                0,
                40,
                265,
                690,
                55,
                0,
            )?;
        }
        self.render_message(335)?;
        self.add_button("&Back", 340, 465, 120, 34, ID_BACK, false)?;
        self.add_button("Cancel", 475, 465, 120, 34, ID_CANCEL, false)?;
        let next = self.add_button("&Next", 610, 465, 120, 34, ID_NEXT, true)?;
        if self.eligible.is_empty() {
            enable(next, false);
        }
        if self.eligible.is_empty() {
            focus(self.control_by_id(ID_REFRESH));
        } else {
            focus(combo);
        }
        Ok(())
    }

    fn render_confirm(&mut self) -> Result<(), AppError> {
        self.render_heading(
            "Step 3 of 5",
            "Confirm erasing this USB",
            "This is the only destructive step. Read the selected device details carefully before continuing.",
        )?;
        let index = self.selected_disk.ok_or_else(|| {
            AppError::Message("the selected USB drive is no longer available".to_owned())
        })?;
        let disk = self.eligible.get(index).ok_or_else(|| {
            AppError::Message("the selected USB drive is no longer available".to_owned())
        })?;
        let release_version = self
            .release
            .as_ref()
            .map(|release| release.authorized.artifact_version())
            .unwrap_or("unavailable");
        self.add_control(
            "STATIC",
            &format!(
                "Release: {release_version}\r\nUSB: {}\r\nCapacity: {} GB\r\nSerial: {}",
                disk.model,
                disk.capacity_bytes / 1_000_000_000,
                disk.serial
            ),
            WS_CHILD | WS_VISIBLE,
            0,
            40,
            165,
            690,
            78,
            0,
        )?;
        let check = self.add_control(
            "BUTTON",
            "I understand that every file on this USB drive will be erased.",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32,
            0,
            40,
            255,
            690,
            28,
            ID_CONFIRM_CHECK,
        )?;
        self.confirmation_check = check;
        let phrase = self.confirmation_phrase.as_deref().ok_or_else(|| {
            AppError::Message("the destructive confirmation is unavailable".to_owned())
        })?;
        self.add_control(
            "STATIC",
            &format!("Type this confirmation exactly:\r\n{phrase}"),
            WS_CHILD | WS_VISIBLE,
            0,
            40,
            298,
            690,
            48,
            0,
        )?;
        let edit = self.add_control(
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL as u32,
            WS_EX_CLIENTEDGE,
            40,
            352,
            690,
            30,
            ID_CONFIRM_TEXT,
        )?;
        self.confirmation_text = edit;
        self.render_message(395)?;
        self.add_button("&Back", 260, 465, 120, 34, ID_BACK, false)?;
        self.add_button("Cancel", 395, 465, 120, 34, ID_CANCEL, false)?;
        self.add_button(
            "&Erase USB and create KernAid",
            530,
            465,
            200,
            34,
            ID_START,
            true,
        )?;
        focus(check);
        Ok(())
    }

    fn render_progress(&mut self) -> Result<(), AppError> {
        self.render_heading(
            "Step 4 of 5",
            "Creating and verifying your USB",
            "Keep the computer awake. Do not remove the USB drive or close this window until verification finishes.",
        )?;
        let status = self.add_control(
            "STATIC",
            "Checking the signed release image before opening the USB...",
            WS_CHILD | WS_VISIBLE,
            0,
            40,
            210,
            690,
            40,
            0,
        )?;
        self.progress_status = status;
        let progress = self.add_control(
            "msctls_progress32",
            "",
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            0,
            40,
            270,
            690,
            28,
            0,
        )?;
        self.progress_bar = progress;
        unsafe {
            // SAFETY: progress is a live progress-bar control.
            SendMessageW(progress, PBM_SETRANGE32, 0, 100);
            SendMessageW(progress, PBM_SETPOS, 0, 0);
        }
        let detail = self.add_control(
            "STATIC",
            "0% complete\r\nThe image is fully hashed before any removable disk is opened. After writing, all 32 GB are read back and checked.",
            WS_CHILD | WS_VISIBLE,
            0,
            40,
            320,
            690,
            70,
            0,
        )?;
        self.progress_detail = detail;
        Ok(())
    }

    fn render_complete(&mut self) -> Result<(), AppError> {
        match self.completion.clone() {
            Some(Completion::Success(result)) => {
                self.render_heading(
                    "Step 5 of 5",
                    "Your KernAid USB is ready",
                    "The complete image was written, flushed, and read back successfully. You can now close this app and safely eject the USB drive.",
                )?;
                let detail = match (&result.report_path, &result.report_warning) {
                    (Some(report), None) => format!(
                        "Verification: Passed\r\nCreation report:\r\n{}",
                        report.display()
                    ),
                    (None, Some(warning)) => {
                        format!("Verification: Passed\r\n\r\nNote: {warning}")
                    }
                    _ => "Verification: Passed".to_owned(),
                };
                self.add_control(
                    "STATIC",
                    &detail,
                    WS_CHILD | WS_VISIBLE,
                    0,
                    40,
                    190,
                    690,
                    100,
                    0,
                )?;
                let close = self.add_button("&Finish", 610, 465, 120, 34, ID_CANCEL, true)?;
                focus(close);
            }
            Some(Completion::Failed(error)) => {
                self.render_heading(
                    "Step 5 of 5",
                    "The USB could not be completed",
                    "KernAid stopped safely. Internal and fixed disks were never eligible. If writing had started, treat the selected USB as incomplete and recreate it.",
                )?;
                self.add_control(
                    "STATIC",
                    &format!("What happened:\r\n{error}"),
                    WS_CHILD | WS_VISIBLE,
                    0,
                    40,
                    190,
                    690,
                    120,
                    0,
                )?;
                self.add_button("Close", 475, 465, 120, 34, ID_CANCEL, false)?;
                let restart =
                    self.add_button("&Start over", 610, 465, 120, 34, ID_RESTART, true)?;
                focus(restart);
            }
            None => {
                return Err(AppError::Message(
                    "the creation result is unavailable".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn render_heading(
        &mut self,
        step: &str,
        title: &str,
        description: &str,
    ) -> Result<(), AppError> {
        self.add_control("STATIC", step, WS_CHILD | WS_VISIBLE, 0, 40, 24, 690, 22, 0)?;
        self.add_control(
            "STATIC",
            title,
            WS_CHILD | WS_VISIBLE,
            0,
            40,
            55,
            690,
            32,
            0,
        )?;
        self.add_control(
            "STATIC",
            description,
            WS_CHILD | WS_VISIBLE,
            0,
            40,
            95,
            690,
            62,
            0,
        )?;
        Ok(())
    }

    fn render_message(&mut self, y: i32) -> Result<(), AppError> {
        if let Some(message) = self.message.clone() {
            self.add_control(
                "STATIC",
                &format!("Action needed: {message}"),
                WS_CHILD | WS_VISIBLE,
                0,
                40,
                y,
                690,
                55,
                0,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_control(
        &mut self,
        class_name: &str,
        text: &str,
        style: u32,
        extended_style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        id: u16,
    ) -> Result<HWND, AppError> {
        let class_name = wide(class_name);
        let text = wide(text);
        let control = unsafe {
            // SAFETY: all strings are nul-terminated for the duration of the call; hwnd and
            // instance are owned by this live wizard window.
            CreateWindowExW(
                extended_style,
                class_name.as_ptr(),
                text.as_ptr(),
                style,
                self.scaled(x),
                self.scaled(y),
                self.scaled(width),
                self.scaled(height),
                self.hwnd,
                id as usize as *mut c_void,
                self.instance,
                null(),
            )
        };
        if control.is_null() {
            return Err(AppError::Message(
                "a Windows wizard control could not be created".to_owned(),
            ));
        }
        let font = unsafe {
            // SAFETY: DEFAULT_GUI_FONT is a process-lifetime stock object.
            GetStockObject(DEFAULT_GUI_FONT)
        };
        unsafe {
            // SAFETY: control is live; stock font remains valid for its lifetime.
            SendMessageW(control, WM_SETFONT, font as WPARAM, 1);
        }
        self.controls.push(control);
        Ok(control)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_button(
        &mut self,
        text: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        id: u16,
        primary: bool,
    ) -> Result<HWND, AppError> {
        self.add_control(
            "BUTTON",
            text,
            WS_CHILD
                | WS_VISIBLE
                | WS_TABSTOP
                | if primary {
                    BS_DEFPUSHBUTTON as u32
                } else {
                    BS_PUSHBUTTON as u32
                },
            0,
            x,
            y,
            width,
            height,
            id,
        )
    }

    fn clear_controls(&mut self) {
        for control in self.controls.drain(..) {
            unsafe {
                // SAFETY: every handle was created as a child owned by this wizard.
                DestroyWindow(control);
            }
        }
        self.disk_combo = null_mut();
        self.confirmation_check = null_mut();
        self.confirmation_text = null_mut();
        self.progress_bar = null_mut();
        self.progress_status = null_mut();
        self.progress_detail = null_mut();
    }

    fn control_by_id(&self, id: u16) -> HWND {
        unsafe {
            // SAFETY: lookup is confined to this live wizard window.
            windows_sys::Win32::UI::WindowsAndMessaging::GetDlgItem(self.hwnd, id as i32)
        }
    }

    fn handle_command(&mut self, id: u16, notification: u16) -> Result<(), AppError> {
        if notification as u32 != BN_CLICKED {
            return Ok(());
        }
        match id {
            ID_BROWSE => self.choose_release(),
            ID_REFRESH => {
                self.refresh_disks();
                self.render()
            }
            ID_BACK => {
                self.message = None;
                self.screen = match self.screen {
                    Screen::Usb => Screen::Image,
                    Screen::Confirm => Screen::Usb,
                    screen => screen,
                };
                self.render()
            }
            ID_NEXT if self.screen == Screen::Image => {
                if self.release.is_none() {
                    return Err(AppError::Message(
                        "choose an authorized release bundle first".to_owned(),
                    ));
                }
                self.message = None;
                self.screen = Screen::Usb;
                self.refresh_disks();
                self.render()
            }
            ID_NEXT if self.screen == Screen::Usb => self.choose_disk(),
            ID_START => self.start_creation(),
            ID_RESTART => {
                self.reset();
                self.render()
            }
            ID_CANCEL => {
                unsafe {
                    // SAFETY: hwnd is the live top-level wizard window.
                    DestroyWindow(self.hwnd);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn choose_release(&mut self) -> Result<(), AppError> {
        let Some(path) = open_release_dialog(self.hwnd)? else {
            return Ok(());
        };
        match load_release_bundle(&path) {
            Ok(release) => {
                self.release = Some(release);
                self.message = None;
            }
            Err(error) => {
                self.release = None;
                self.message = Some(format!(
                    "This release cannot be used. {error}. Download the complete KernAid release bundle again."
                ));
            }
        }
        self.render()
    }

    fn refresh_disks(&mut self) {
        self.backend = None;
        self.snapshot.clear();
        self.eligible.clear();
        self.selected_disk = None;
        let Some(release) = self.release.as_ref() else {
            self.message = Some("the authorized release is unavailable".to_owned());
            return;
        };
        let mut backend = WindowsDiskBackend::new();
        match backend.enumerate() {
            Ok(snapshot) => {
                self.eligible = eligible_disks(&snapshot, &release.authorized);
                self.snapshot = snapshot;
                self.backend = Some(backend);
                self.message = None;
            }
            Err(error) => {
                self.message = Some(format!(
                    "Windows could not inspect removable disks safely: {error}"
                ));
            }
        }
    }

    fn choose_disk(&mut self) -> Result<(), AppError> {
        let index = unsafe {
            // SAFETY: disk_combo is live while the USB screen is displayed.
            SendMessageW(self.disk_combo, CB_GETCURSEL, 0, 0)
        };
        if index == CB_ERR as LRESULT {
            return Err(AppError::Message(
                "select one removable USB drive".to_owned(),
            ));
        }
        let index = usize::try_from(index)
            .map_err(|_| AppError::Message("the USB selection is invalid".to_owned()))?;
        let eligible = self
            .eligible
            .get(index)
            .ok_or_else(|| AppError::Message("the USB selection is invalid".to_owned()))?;
        let selection = select_disk(&self.snapshot, eligible)?;
        self.selected_disk = Some(index);
        self.confirmation_phrase = Some(selection.confirmation_phrase().to_owned());
        self.message = None;
        self.screen = Screen::Confirm;
        self.render()
    }

    fn start_creation(&mut self) -> Result<(), AppError> {
        let checked = unsafe {
            // SAFETY: confirmation_check is a live checkbox on the confirmation screen.
            SendMessageW(self.confirmation_check, BM_GETCHECK, 0, 0)
        } == BST_CHECKED as LRESULT;
        if !checked {
            return Err(AppError::Message(
                "check the erase acknowledgement before continuing".to_owned(),
            ));
        }
        let phrase = window_text(self.confirmation_text, 160)?;
        let index = self
            .selected_disk
            .ok_or_else(|| AppError::Message("the selected USB drive is unavailable".to_owned()))?;
        let eligible = self
            .eligible
            .get(index)
            .ok_or_else(|| AppError::Message("the selected USB drive is unavailable".to_owned()))?;
        let confirmed = select_disk(&self.snapshot, eligible)?.confirm(&phrase)?;
        let backend = self.backend.take().ok_or_else(|| {
            AppError::Message("the removable USB inventory is unavailable".to_owned())
        })?;
        let release = self
            .release
            .take()
            .ok_or_else(|| AppError::Message("the authorized release is unavailable".to_owned()))?;
        self.running = true;
        self.message = None;
        self.screen = Screen::Progress;
        self.render()?;
        spawn_creation(self.hwnd, backend, confirmed, release);
        Ok(())
    }

    fn apply_progress(&mut self, update: ProgressUpdate) {
        if self.screen != Screen::Progress || !self.running {
            return;
        }
        set_text(self.progress_status, update.status);
        unsafe {
            // SAFETY: progress_bar is live for the duration of the worker.
            SendMessageW(self.progress_bar, PBM_SETPOS, update.percent as WPARAM, 0);
        }
        let detail = format!("{}% complete", update.percent);
        set_text(self.progress_detail, &detail);
    }

    fn complete(&mut self, completion: Completion) -> Result<(), AppError> {
        self.running = false;
        self.completion = Some(completion);
        self.screen = Screen::Complete;
        self.render()
    }

    fn reset(&mut self) {
        self.screen = Screen::Image;
        self.message = None;
        self.release = None;
        self.backend = None;
        self.snapshot.clear();
        self.eligible.clear();
        self.selected_disk = None;
        self.confirmation_phrase = None;
        self.completion = None;
        self.running = false;
    }
}

pub(crate) fn run() -> Result<(), AppError> {
    unsafe {
        // SAFETY: process DPI awareness is configured before creating any window.
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let common_controls = INITCOMMONCONTROLSEX {
        dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: ICC_PROGRESS_CLASS,
    };
    if unsafe {
        // SAFETY: common_controls is a valid initialized descriptor.
        InitCommonControlsEx(&common_controls)
    } == 0
    {
        return Err(AppError::Message(
            "Windows progress controls are unavailable".to_owned(),
        ));
    }
    let instance = unsafe {
        // SAFETY: null requests the current executable module.
        GetModuleHandleW(null())
    };
    if instance.is_null() {
        return Err(AppError::Io(std::io::Error::last_os_error()));
    }
    let class_name = wide(CLASS_NAME);
    let class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: unsafe {
            // SAFETY: IDI_APPLICATION is a predefined shared icon.
            LoadIconW(null_mut(), IDI_APPLICATION)
        },
        hCursor: unsafe {
            // SAFETY: IDC_ARROW is a predefined shared cursor.
            LoadCursorW(null_mut(), IDC_ARROW)
        },
        hbrBackground: (COLOR_WINDOW + 1) as usize as HBRUSH,
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    if unsafe {
        // SAFETY: class fields point to process-lifetime callbacks or live local strings for this call.
        RegisterClassW(&class)
    } == 0
    {
        return Err(AppError::Message(
            "the KernAid wizard window could not be registered".to_owned(),
        ));
    }
    let dpi = unsafe {
        // SAFETY: GetDpiForSystem has no pointer preconditions.
        GetDpiForSystem()
    }
    .max(96);
    let state_pointer = Box::into_raw(Box::new(Wizard::new(instance, dpi)));
    let title = wide(WINDOW_TITLE);
    let hwnd = unsafe {
        // SAFETY: state_pointer remains owned by this function for the message-loop lifetime.
        CreateWindowExW(
            WS_EX_APPWINDOW | WS_EX_CONTROLPARENT,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            WINDOW_WIDTH.saturating_mul(dpi as i32) / 96,
            WINDOW_HEIGHT.saturating_mul(dpi as i32) / 96,
            null_mut(),
            null_mut(),
            instance,
            state_pointer.cast(),
        )
    };
    if hwnd.is_null() {
        unsafe {
            // SAFETY: ownership was not transferred because window creation failed.
            drop(Box::from_raw(state_pointer));
        }
        return Err(AppError::Message(
            "the KernAid wizard window could not be created".to_owned(),
        ));
    }
    if let Err(error) = unsafe {
        // SAFETY: successful window creation stored this live pointer during WM_NCCREATE.
        (&mut *state_pointer).render()
    } {
        unsafe {
            // SAFETY: the window is live and state ownership remains with this function.
            DestroyWindow(hwnd);
            drop(Box::from_raw(state_pointer));
        }
        return Err(error);
    }
    unsafe {
        // SAFETY: hwnd is a newly created top-level window.
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
    }
    let mut message = MSG::default();
    loop {
        let result = unsafe {
            // SAFETY: message is writable and the filter accepts all thread messages.
            GetMessageW(&mut message, null_mut(), 0, 0)
        };
        if result == -1 {
            let error = AppError::Io(std::io::Error::last_os_error());
            unsafe {
                // SAFETY: destroy detaches state from the window before reclaiming the Box.
                DestroyWindow(hwnd);
                drop(Box::from_raw(state_pointer));
            }
            return Err(error);
        }
        if result == 0 {
            break;
        }
        let handled = unsafe {
            // SAFETY: hwnd remains live until WM_DESTROY terminates the loop.
            IsDialogMessageW(hwnd, &message)
        };
        if handled == 0 {
            unsafe {
                // SAFETY: message was produced by GetMessageW.
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    unsafe {
        // SAFETY: the window is destroyed and no further window message can access this state.
        drop(Box::from_raw(state_pointer));
    }
    Ok(())
}

pub(crate) fn show_fatal_error(message: &str) {
    show_message(null_mut(), message, true);
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        let create = unsafe {
            // SAFETY: WM_NCCREATE supplies a valid CREATESTRUCTW pointer.
            &*(lparam as *const CREATESTRUCTW)
        };
        let state = create.lpCreateParams.cast::<Wizard>();
        if state.is_null() {
            return 0;
        }
        unsafe {
            // SAFETY: state was allocated by Box and remains valid until WM_NCDESTROY.
            (*state).hwnd = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize);
        }
        return 1;
    }

    let state_pointer = unsafe {
        // SAFETY: querying window-owned user data is valid for any message.
        GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Wizard
    };
    match message {
        WM_COMMAND if !state_pointer.is_null() => {
            let id = (wparam & 0xffff) as u16;
            let notification = ((wparam >> 16) & 0xffff) as u16;
            let state = unsafe {
                // SAFETY: state_pointer is window-owned and command dispatch is serialized.
                &mut *state_pointer
            };
            if let Err(error) = state.handle_command(id, notification) {
                show_message(hwnd, &error.to_string(), false);
            }
            0
        }
        WM_WIZARD_PROGRESS if !state_pointer.is_null() && lparam != 0 => {
            let update = unsafe {
                // SAFETY: the worker transfers exactly one boxed ProgressUpdate with this message.
                Box::from_raw(lparam as *mut ProgressUpdate)
            };
            let state = unsafe {
                // SAFETY: state_pointer is window-owned and messages are serialized.
                &mut *state_pointer
            };
            state.apply_progress(*update);
            0
        }
        WM_WIZARD_COMPLETE if !state_pointer.is_null() && lparam != 0 => {
            let completion = unsafe {
                // SAFETY: the worker transfers exactly one boxed Completion with this message.
                Box::from_raw(lparam as *mut Completion)
            };
            let state = unsafe {
                // SAFETY: state_pointer is window-owned and messages are serialized.
                &mut *state_pointer
            };
            if let Err(error) = state.complete(*completion) {
                show_message(hwnd, &error.to_string(), true);
            }
            0
        }
        WM_CLOSE if !state_pointer.is_null() => {
            let state = unsafe {
                // SAFETY: state_pointer is window-owned and close dispatch is serialized.
                &mut *state_pointer
            };
            if state.running {
                show_message(
                    hwnd,
                    "KernAid is still writing or verifying the USB. Keep this window open and do not remove the drive.",
                    false,
                );
            } else {
                unsafe {
                    // SAFETY: hwnd is the current live top-level window.
                    DestroyWindow(hwnd);
                }
            }
            0
        }
        WM_DESTROY => {
            unsafe {
                // SAFETY: ends this UI thread's message loop.
                PostQuitMessage(0);
            }
            0
        }
        WM_NCDESTROY if !state_pointer.is_null() => {
            unsafe {
                // SAFETY: this terminal message only detaches the function-owned state pointer.
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            0
        }
        _ => unsafe {
            // SAFETY: unhandled messages are delegated to the system default procedure.
            DefWindowProcW(hwnd, message, wparam, lparam)
        },
    }
}

fn spawn_creation(
    hwnd: HWND,
    backend: WindowsDiskBackend,
    confirmed: kernaid_media_creator_core::ConfirmedSelection,
    release: LoadedRelease,
) {
    let window = hwnd as usize;
    thread::spawn(move || {
        let mut last_update: Option<(MediaPhase, u32)> = None;
        let result = create_release_media(backend, confirmed, release, |progress| {
            let percent = overall_percent(progress);
            if last_update == Some((progress.phase, percent)) {
                return;
            }
            last_update = Some((progress.phase, percent));
            let status = match progress.phase {
                MediaPhase::ValidatingArchive => {
                    "Checking the signed release image before opening the USB..."
                }
                MediaPhase::WritingUsb => "Writing KernAid to the removable USB drive...",
                MediaPhase::VerifyingUsb => "Reading the entire USB back to verify every byte...",
            };
            post_boxed(
                window,
                WM_WIZARD_PROGRESS,
                Box::new(ProgressUpdate { percent, status }),
            );
        })
        .map(Completion::Success)
        .unwrap_or_else(|error| Completion::Failed(error.to_string()));
        post_boxed(window, WM_WIZARD_COMPLETE, Box::new(result));
    });
}

fn overall_percent(progress: MediaProgress) -> u32 {
    let (base, span) = match progress.phase {
        MediaPhase::ValidatingArchive => (0_u32, 10_u32),
        MediaPhase::WritingUsb => (10_u32, 60_u32),
        MediaPhase::VerifyingUsb => (70_u32, 30_u32),
    };
    if progress.total_bytes == 0 {
        return base;
    }
    let within = (u128::from(progress.completed_bytes.min(progress.total_bytes)) * u128::from(span)
        / u128::from(progress.total_bytes)) as u32;
    base + within
}

fn post_boxed<T>(window: usize, message: u32, value: Box<T>) {
    let pointer = Box::into_raw(value);
    let posted = unsafe {
        // SAFETY: the pointer is transferred to the UI thread only when PostMessage succeeds.
        PostMessageW(window as HWND, message, 0, pointer as LPARAM)
    };
    if posted == 0 {
        unsafe {
            // SAFETY: message delivery failed, so ownership was not transferred.
            drop(Box::from_raw(pointer));
        }
    }
}

fn open_release_dialog(owner: HWND) -> Result<Option<PathBuf>, AppError> {
    let mut path = vec![0_u16; 32_768];
    let filter = "KernAid signed release bundle\0KernAid-Rescue-amd64.media-bundle.json\0\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    let title = wide("Choose the KernAid release bundle");
    let mut options = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        lpstrFilter: filter.as_ptr(),
        lpstrFile: path.as_mut_ptr(),
        nMaxFile: path.len() as u32,
        lpstrTitle: title.as_ptr(),
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_DONTADDTORECENT,
        ..OPENFILENAMEW::default()
    };
    let selected = unsafe {
        // SAFETY: options points to correctly sized writable buffers for the duration of the call.
        GetOpenFileNameW(&mut options)
    };
    if selected == 0 {
        let error = unsafe {
            // SAFETY: reads the calling thread's common-dialog status.
            CommDlgExtendedError()
        };
        if error == 0 {
            return Ok(None);
        }
        return Err(AppError::Message(
            "Windows could not open the release-bundle picker".to_owned(),
        ));
    }
    let length = path
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| AppError::Message("the selected release path is too long".to_owned()))?;
    Ok(Some(PathBuf::from(OsString::from_wide(&path[..length]))))
}

fn window_text(window: HWND, maximum: usize) -> Result<String, AppError> {
    let length = unsafe {
        // SAFETY: window is a live edit control.
        GetWindowTextLengthW(window)
    };
    if length < 0 || length as usize > maximum {
        return Err(AppError::Message(
            "the confirmation text is too long".to_owned(),
        ));
    }
    let mut value = vec![0_u16; length as usize + 1];
    let copied = unsafe {
        // SAFETY: value provides length+1 writable UTF-16 code units.
        GetWindowTextW(window, value.as_mut_ptr(), value.len() as i32)
    };
    if copied < 0 {
        return Err(AppError::Message(
            "the confirmation text could not be read".to_owned(),
        ));
    }
    String::from_utf16(&value[..copied as usize])
        .map_err(|_| AppError::Message("the confirmation text is invalid".to_owned()))
}

fn set_text(window: HWND, value: &str) {
    if window.is_null() {
        return;
    }
    let value = wide(value);
    unsafe {
        // SAFETY: window is live and value is nul-terminated for the call.
        SetWindowTextW(window, value.as_ptr());
    }
}

fn enable(window: HWND, enabled: bool) {
    if window.is_null() {
        return;
    }
    unsafe {
        // SAFETY: window is a live control.
        EnableWindow(window, i32::from(enabled));
    }
}

fn focus(window: HWND) {
    if window.is_null() {
        return;
    }
    unsafe {
        // SAFETY: window is a live visible control on the UI thread.
        SetFocus(window);
    }
}

fn show_message(owner: HWND, message: &str, fatal: bool) {
    let title = wide(if fatal {
        "KernAid Media Creator — Error"
    } else {
        "KernAid Media Creator"
    });
    let message = wide(message);
    unsafe {
        // SAFETY: strings are nul-terminated for this synchronous call.
        MessageBoxW(
            owner,
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_TASKMODAL | if fatal { MB_ICONERROR } else { MB_ICONWARNING },
        );
    }
}

fn wide(value: &str) -> Vec<u16> {
    value
        .chars()
        .map(|character| {
            if character == '\0' {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect::<String>()
        .encode_utf16()
        .chain(Some(0))
        .collect()
}
