//! Desktop graphical user interface built with eframe and egui.

mod dialogs;

use std::collections::BTreeSet;

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Frame, Layout, Margin, Pos2, Rect, RichText,
    ScrollArea, Sense, Stroke, TextStyle, Ui, Vec2,
};

use crate::config::{AppConfig, ThemeMode};
use crate::model::{
    compare_sids, normalize_server_name, BuiltInPrincipal, GroupAccount, GroupMember, UserAccount,
};
use crate::winapi::{
    is_process_elevated, local_computer_name, local_tz_offset_hours, AccountBackend, WindowsBackend,
};

pub use dialogs::ActiveDialog;

/// Global typography scale factor applied to all egui text styles.
pub const FONT_SCALE: f32 = 1.5_f32;

/// Embedded 256x256 RGBA application icon PNG.
const APP_ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");

/// Decodes the embedded application icon PNG into RGBA8 pixels and dimensions.
pub(crate) fn load_app_icon_rgba() -> Option<(Vec<u8>, u32, u32)> {
    let img = image::load_from_memory(APP_ICON_PNG).ok()?.to_rgba8();
    let (w, h) = img.dimensions();
    Some((img.into_raw(), w, h))
}

/// Builds eframe `IconData` from the embedded PNG for the native window titlebar and taskbar.
fn load_viewport_icon() -> Option<egui::IconData> {
    let (rgba, width, height) = load_app_icon_rgba()?;
    Some(egui::IconData {
        rgba,
        width,
        height,
    })
}

/// Selects which category is active for the chosen computer in the left tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewKind {
    /// Overview node showing Users, Groups, and Built-in categories.
    Overview,
    /// Local user accounts table.
    Users,
    /// Local security groups table.
    Groups,
    /// Built-in well-known security principals table.
    BuiltIn,
}

impl ViewKind {
    /// Returns the display label for the category node.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Users => "Users",
            Self::Groups => "Groups",
            Self::BuiltIn => "Built-in Security Principals",
        }
    }
}

/// Sort column selector for the main table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    /// Primary account or principal name.
    Name,
    /// User full name or built-in domain.
    Secondary,
    /// User status column.
    Status,
    /// Description or SID column.
    Detail,
}

/// Holds cached account data for one local or remote Windows machine.
#[derive(Debug, Clone)]
pub struct MachineEntry {
    /// User-facing hostname (for example, "DESKTOP-ABC").
    pub display_name: String,
    /// Normalized NetAPI server target (`None` for local, `Some("\\HOST")` for remote).
    pub server_target: Option<String>,
    /// True when this entry represents the local host computer.
    pub is_local: bool,
    /// Cached local user accounts.
    pub users: Vec<UserAccount>,
    /// Cached local security groups.
    pub groups: Vec<GroupAccount>,
    /// Cached well-known security principals.
    pub builtins: Vec<BuiltInPrincipal>,
    /// Last refresh error message, if any.
    pub last_error: Option<String>,
}

impl MachineEntry {
    /// Returns the sidebar title for this computer.
    pub fn sidebar_title(&self) -> String {
        if self.is_local {
            format!("{} (This Computer)", self.display_name)
        } else {
            self.display_name.clone()
        }
    }
}

/// Severity level for status notifications at the bottom of the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    /// Neutral operational confirmation.
    Info,
    /// Non-fatal caution or permission hint.
    Warning,
    /// Operation failure.
    Error,
}

/// Transient notification banner displayed in the status footer.
#[derive(Debug, Clone)]
pub struct StatusNotice {
    /// Severity level.
    pub kind: NoticeKind,
    /// Message text.
    pub text: String,
}

/// Color palette calibrated for crisp neutral Dark and clean white Light modes.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    /// Primary background fill.
    pub bg_canvas: Color32,
    /// Sidebar and secondary panel background.
    pub bg_panel: Color32,
    /// Elevated table header and card fill.
    pub bg_surface: Color32,
    /// Subtle alternating table row fill.
    pub row_alt: Color32,
    /// Selected row highlight fill.
    pub row_selected: Color32,
    /// Standard divider and border stroke color.
    pub border: Color32,
    /// Primary text color.
    pub text_primary: Color32,
    /// Secondary muted text color.
    pub text_muted: Color32,
    /// Primary action accent color.
    pub accent: Color32,
    /// Crisp high-contrast red for disabled-user badge (Issue #7) and errors.
    pub danger: Color32,
    /// Warning amber for locked accounts and standard-user notices.
    pub warning: Color32,
    /// Success green for active states and elevated badge.
    pub success: Color32,
}

impl Palette {
    /// Returns the palette matching the active Dark or Light theme.
    pub const fn for_theme(theme: ThemeMode) -> Self {
        match theme {
            ThemeMode::Dark => Self {
                bg_canvas: Color32::from_rgb(22, 24, 29),
                bg_panel: Color32::from_rgb(28, 31, 38),
                bg_surface: Color32::from_rgb(36, 40, 49),
                row_alt: Color32::from_rgb(26, 29, 35),
                row_selected: Color32::from_rgb(41, 66, 102),
                border: Color32::from_rgb(56, 62, 74),
                text_primary: Color32::from_rgb(236, 240, 246),
                text_muted: Color32::from_rgb(160, 170, 186),
                accent: Color32::from_rgb(59, 130, 246),
                danger: Color32::from_rgb(217, 45, 32),
                warning: Color32::from_rgb(234, 154, 38),
                success: Color32::from_rgb(34, 160, 107),
            },
            ThemeMode::Light => Self {
                bg_canvas: Color32::from_rgb(255, 255, 255),
                bg_panel: Color32::from_rgb(245, 247, 250),
                bg_surface: Color32::from_rgb(236, 240, 245),
                row_alt: Color32::from_rgb(248, 250, 252),
                row_selected: Color32::from_rgb(214, 231, 252),
                border: Color32::from_rgb(209, 217, 227),
                text_primary: Color32::from_rgb(22, 27, 34),
                text_muted: Color32::from_rgb(92, 103, 118),
                accent: Color32::from_rgb(29, 99, 216),
                danger: Color32::from_rgb(217, 45, 32),
                warning: Color32::from_rgb(181, 102, 12),
                success: Color32::from_rgb(20, 128, 82),
            },
        }
    }
}

/// Main desktop application state.
pub struct AccountManagerApp {
    /// Operating system backend implementation.
    pub(crate) backend: WindowsBackend,
    /// Persistent user configuration.
    pub(crate) config: AppConfig,
    /// Local computer name detected at startup.
    pub(crate) local_name: String,
    /// Whether the process holds administrative elevation.
    pub(crate) is_elevated: bool,
    /// Local UTC timezone offset in hours for logon-hour editing.
    pub(crate) tz_offset_hours: i32,
    /// Connected machines (index 0 is always the local computer).
    pub(crate) machines: Vec<MachineEntry>,
    /// Index of the selected machine in `machines`.
    pub(crate) selected_machine: usize,
    /// Active table view for the selected machine.
    pub(crate) active_view: ViewKind,
    /// Quick Search filter text for the current view.
    pub(crate) quick_search: String,
    /// Active sort column.
    pub(crate) sort_column: SortColumn,
    /// Sort direction (true = ascending).
    pub(crate) sort_ascending: bool,
    /// Selected item names in the current table.
    pub(crate) selected_items: BTreeSet<String>,
    /// Currently open modal dialog, if any.
    pub(crate) dialog: Option<ActiveDialog>,
    /// Status message displayed at the bottom bar.
    pub(crate) notice: Option<StatusNotice>,
    /// Cached texture handle for the custom application icon shown in the About dialog.
    pub(crate) about_icon_texture: Option<egui::TextureHandle>,
    /// Tracks whether typography and visuals were initialized.
    style_initialized: bool,
}

impl AccountManagerApp {
    /// Initializes the application and loads local machine accounts.
    pub fn new() -> Self {
        let config = AppConfig::load_or_default();
        let local_name = local_computer_name();
        let is_elevated = is_process_elevated();
        let tz_offset_hours = local_tz_offset_hours();

        let local_entry = MachineEntry {
            display_name: local_name.clone(),
            server_target: None,
            is_local: true,
            users: Vec::new(),
            groups: Vec::new(),
            builtins: Vec::new(),
            last_error: None,
        };

        let mut app = Self {
            backend: WindowsBackend,
            config,
            local_name,
            is_elevated,
            tz_offset_hours,
            machines: vec![local_entry],
            selected_machine: 0,
            active_view: ViewKind::Users,
            quick_search: String::new(),
            sort_column: SortColumn::Name,
            sort_ascending: true,
            selected_items: BTreeSet::new(),
            dialog: None,
            notice: None,
            about_icon_texture: None,
            style_initialized: false,
        };

        app.refresh_machine(0);
        if !app.is_elevated {
            app.set_notice(
                NoticeKind::Warning,
                "Running as standard user. Local accounts are read-only unless elevated as Administrator.",
            );
        }
        app
    }

    /// Lazily loads and returns the application icon texture for the About dialog.
    pub(crate) fn ensure_about_icon_texture(
        &mut self,
        ctx: &egui::Context,
    ) -> Option<egui::TextureId> {
        if self.about_icon_texture.is_none() {
            if let Some((rgba, w, h)) = load_app_icon_rgba() {
                let image =
                    egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
                let handle =
                    ctx.load_texture("lusrmgr_about_icon", image, egui::TextureOptions::LINEAR);
                self.about_icon_texture = Some(handle);
            }
        }
        self.about_icon_texture
            .as_ref()
            .map(egui::TextureHandle::id)
    }

    /// Sets the bottom status notice message.
    pub(crate) fn set_notice(&mut self, kind: NoticeKind, text: impl Into<String>) {
        self.notice = Some(StatusNotice {
            kind,
            text: text.into(),
        });
    }

    /// Returns a reference to the active machine entry.
    pub(crate) fn current_machine(&self) -> &MachineEntry {
        let idx = self.selected_machine.min(self.machines.len() - 1);
        &self.machines[idx]
    }

    /// Reloads users, groups, and built-in principals for the specified machine index.
    pub(crate) fn refresh_machine(&mut self, machine_idx: usize) {
        let Some(machine) = self.machines.get(machine_idx) else {
            return;
        };
        let target = machine.server_target.clone();
        let users_res = self.backend.list_users(target.as_deref());
        let groups_res = self.backend.list_groups(target.as_deref());
        let builtin_res = self.backend.list_builtin_principals(target.as_deref());

        let mut errors = Vec::new();
        if let Some(entry) = self.machines.get_mut(machine_idx) {
            match users_res {
                Ok(users) => entry.users = users,
                Err(err) => errors.push(format!("Users: {err}")),
            }
            match groups_res {
                Ok(groups) => entry.groups = groups,
                Err(err) => errors.push(format!("Groups: {err}")),
            }
            match builtin_res {
                Ok(builtins) => entry.builtins = builtins,
                Err(err) => errors.push(format!("Built-in: {err}")),
            }
            entry.last_error = if errors.is_empty() {
                None
            } else {
                Some(errors.join(" | "))
            };
        }

        if let Some(err_text) = self.machines[machine_idx].last_error.clone() {
            self.set_notice(NoticeKind::Error, err_text);
        }
    }

    /// Connects a new remote computer entry and loads its account data.
    pub(crate) fn connect_remote_machine(
        &mut self,
        host_input: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<(), String> {
        let clean = host_input.trim().trim_start_matches('\\');
        if clean.is_empty() {
            return Err("Enter a remote computer name or IP address.".to_string());
        }
        if let Some(existing_idx) = self
            .machines
            .iter()
            .position(|m| m.display_name.eq_ignore_ascii_case(clean))
        {
            self.selected_machine = existing_idx;
            self.refresh_machine(existing_idx);
            self.set_notice(NoticeKind::Info, format!("Switched to {clean}."));
            return Ok(());
        }

        let target = normalize_server_name(clean, &self.local_name);
        if target.is_none() {
            self.selected_machine = 0;
            self.refresh_machine(0);
            return Ok(());
        }

        if username.is_some_and(|u| !u.trim().is_empty()) || password.is_some_and(|p| !p.is_empty())
        {
            self.backend
                .connect_remote(clean, username, password)
                .map_err(|e| e.to_string())?;
        }

        let users = self
            .backend
            .list_users(target.as_deref())
            .map_err(|e| e.to_string())?;
        let groups = self
            .backend
            .list_groups(target.as_deref())
            .unwrap_or_default();
        let builtins = self
            .backend
            .list_builtin_principals(target.as_deref())
            .unwrap_or_default();

        self.machines.push(MachineEntry {
            display_name: clean.to_string(),
            server_target: target,
            is_local: false,
            users,
            groups,
            builtins,
            last_error: None,
        });
        self.selected_machine = self.machines.len() - 1;
        self.selected_items.clear();
        self.config.remember_host(clean);
        let _ = self.config.save();
        self.set_notice(NoticeKind::Info, format!("Connected to {clean}."));
        Ok(())
    }

    /// Disconnects and removes a remote machine entry from the sidebar.
    pub(crate) fn disconnect_machine(&mut self, machine_idx: usize) {
        if machine_idx == 0 || machine_idx >= self.machines.len() {
            return;
        }
        let name = self.machines[machine_idx].display_name.clone();
        let _ = self.backend.disconnect_remote(&name);
        self.machines.remove(machine_idx);
        if self.selected_machine >= self.machines.len() {
            self.selected_machine = 0;
        }
        self.selected_items.clear();
        self.set_notice(NoticeKind::Info, format!("Disconnected from {name}."));
    }

    /// Opens the Edit User dialog after loading level-4 properties and group memberships.
    pub(crate) fn open_edit_user(&mut self, machine_idx: usize, username: &str) {
        let Some(machine) = self.machines.get(machine_idx) else {
            return;
        };
        let target = machine.server_target.clone();
        let detail = match self.backend.get_user(target.as_deref(), username) {
            Ok(user) => user,
            Err(err) => {
                self.set_notice(NoticeKind::Error, err.to_string());
                return;
            }
        };
        let member_groups = self
            .backend
            .get_user_groups(target.as_deref(), username)
            .unwrap_or_default();
        self.dialog = Some(dialogs::make_edit_user_dialog(
            machine_idx,
            detail,
            member_groups,
        ));
    }

    /// Opens the Edit Group dialog after loading current members with local disabled states.
    pub(crate) fn open_edit_group(&mut self, machine_idx: usize, group_name: &str) {
        let Some(machine) = self.machines.get(machine_idx) else {
            return;
        };
        let Some(group) = machine
            .groups
            .iter()
            .find(|g| g.name.eq_ignore_ascii_case(group_name))
            .cloned()
        else {
            return;
        };
        let target = machine.server_target.clone();
        let members =
            match self
                .backend
                .list_group_members(target.as_deref(), &group.name, &machine.users)
            {
                Ok(list) => list,
                Err(err) => {
                    self.set_notice(NoticeKind::Error, err.to_string());
                    Vec::new()
                }
            };
        self.dialog = Some(dialogs::make_edit_group_dialog(machine_idx, group, members));
    }

    /// Opens the Delete Confirmation dialog or deletes directly when confirmation is disabled.
    pub(crate) fn request_delete_selected(&mut self) {
        let targets: Vec<String> = self.selected_items.iter().cloned().collect();
        if targets.is_empty() {
            return;
        }
        let is_user = match self.active_view {
            ViewKind::Users => true,
            ViewKind::Groups => false,
            _ => return,
        };
        if self.config.warn_delete {
            self.dialog = Some(ActiveDialog::ConfirmDelete {
                machine_idx: self.selected_machine,
                is_user,
                names: targets,
            });
        } else {
            self.execute_delete(self.selected_machine, is_user, &targets);
        }
    }

    /// Deletes the given user or group names from the target machine.
    pub(crate) fn execute_delete(&mut self, machine_idx: usize, is_user: bool, names: &[String]) {
        let Some(machine) = self.machines.get(machine_idx) else {
            return;
        };
        let target = machine.server_target.clone();
        let mut deleted = 0usize;
        let mut failures = Vec::new();
        for name in names {
            let res = if is_user {
                self.backend.delete_user(target.as_deref(), name)
            } else {
                self.backend.delete_group(target.as_deref(), name)
            };
            match res {
                Ok(()) => deleted += 1,
                Err(err) => failures.push(format!("{name}: {err}")),
            }
        }
        self.selected_items.clear();
        self.refresh_machine(machine_idx);
        if failures.is_empty() {
            let noun = if is_user { "user" } else { "group" };
            let suffix = if deleted == 1 { "" } else { "s" };
            self.set_notice(
                NoticeKind::Info,
                format!("Deleted {deleted} {noun}{suffix}."),
            );
        } else {
            self.set_notice(NoticeKind::Error, failures.join(" | "));
        }
    }

    /// Applies typography scaling (1.5x) and clean theme visuals to the egui context.
    fn apply_theme_and_fonts(&mut self, ctx: &egui::Context) {
        let palette = Palette::for_theme(self.config.theme);
        let mut visuals = match self.config.theme {
            ThemeMode::Dark => egui::Visuals::dark(),
            ThemeMode::Light => egui::Visuals::light(),
        };

        visuals.panel_fill = palette.bg_canvas;
        visuals.window_fill = palette.bg_panel;
        visuals.extreme_bg_color = palette.bg_surface;
        visuals.faint_bg_color = palette.row_alt;
        visuals.selection.bg_fill = palette.row_selected;
        visuals.selection.stroke = Stroke::new(1.0_f32, palette.accent);
        visuals.window_stroke = Stroke::new(1.0_f32, palette.border);
        visuals.window_corner_radius = CornerRadius::same(6);

        let button_radius = CornerRadius::same(4);
        visuals.widgets.noninteractive.corner_radius = button_radius;
        visuals.widgets.inactive.corner_radius = button_radius;
        visuals.widgets.hovered.corner_radius = button_radius;
        visuals.widgets.active.corner_radius = button_radius;
        visuals.widgets.open.corner_radius = button_radius;

        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, palette.text_primary);
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, palette.text_primary);
        visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, palette.text_primary);
        visuals.widgets.inactive.bg_fill = palette.bg_surface;
        visuals.widgets.inactive.weak_bg_fill = palette.bg_surface;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, palette.border);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, palette.accent);

        let mut style = (*ctx.style()).clone();
        style.visuals = visuals;
        style.spacing.item_spacing = Vec2::new(8.0_f32, 6.0_f32);
        style.spacing.button_padding = Vec2::new(10.0_f32, 5.0_f32);
        style.spacing.interact_size.y = 28.0_f32;

        if !self.style_initialized {
            style.text_styles = [
                (
                    TextStyle::Small,
                    FontId::proportional(10.0_f32 * FONT_SCALE),
                ),
                (TextStyle::Body, FontId::proportional(11.5_f32 * FONT_SCALE)),
                (
                    TextStyle::Button,
                    FontId::proportional(11.5_f32 * FONT_SCALE),
                ),
                (
                    TextStyle::Heading,
                    FontId::proportional(15.0_f32 * FONT_SCALE),
                ),
                (
                    TextStyle::Monospace,
                    FontId::proportional(11.0_f32 * FONT_SCALE),
                ),
            ]
            .into();
            self.style_initialized = true;
        }
        ctx.set_style(style);
    }

    /// Renders the top command toolbar.
    fn render_top_bar(&mut self, ctx: &egui::Context, palette: Palette) {
        egui::TopBottomPanel::top("top_toolbar")
            .frame(
                Frame::NONE
                    .fill(palette.bg_panel)
                    .inner_margin(Margin::symmetric(12, 8))
                    .stroke(Stroke::new(1.0_f32, palette.border)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Local User and Group Management")
                            .heading()
                            .strong()
                            .color(palette.text_primary),
                    );

                    ui.separator();

                    if ui.button("Refresh").clicked() {
                        self.refresh_machine(self.selected_machine);
                        self.set_notice(NoticeKind::Info, "Refreshed account lists.");
                    }
                    if ui.button("Connect Remote...").clicked() {
                        self.dialog = Some(dialogs::make_connect_dialog(&self.config.recent_hosts));
                    }
                    if ui.button("Global Search").clicked() {
                        self.dialog = Some(dialogs::make_global_search_dialog());
                    }
                    if ui.button("Settings").clicked() {
                        self.dialog = Some(ActiveDialog::Settings);
                    }
                    if ui.button("About").clicked() {
                        self.dialog = Some(ActiveDialog::About);
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button(self.config.theme.toggle_label()).clicked() {
                            self.config.theme = self.config.theme.toggled();
                            let _ = self.config.save();
                        }

                        let (badge_text, badge_color) = if self.is_elevated {
                            ("Administrator", palette.success)
                        } else {
                            ("Standard User", palette.warning)
                        };
                        Frame::NONE
                            .fill(palette.bg_surface)
                            .stroke(Stroke::new(1.0_f32, badge_color))
                            .corner_radius(CornerRadius::same(4))
                            .inner_margin(Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(RichText::new(badge_text).small().color(badge_color));
                            });
                    });
                });
            });
    }

    /// Renders the left computer and category tree sidebar.
    fn render_sidebar(&mut self, ctx: &egui::Context, palette: Palette) {
        egui::SidePanel::left("machine_tree")
            .default_width(270.0_f32)
            .min_width(220.0_f32)
            .max_width(400.0_f32)
            .frame(
                Frame::NONE
                    .fill(palette.bg_panel)
                    .inner_margin(Margin::symmetric(10, 10))
                    .stroke(Stroke::new(1.0_f32, palette.border)),
            )
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("Computers")
                        .strong()
                        .color(palette.text_muted),
                );
                ui.add_space(4.0_f32);

                let mut switch_to: Option<(usize, ViewKind)> = None;
                let mut disconnect_target: Option<usize> = None;

                ScrollArea::vertical().show(ui, |ui| {
                    for (idx, machine) in self.machines.iter().enumerate() {
                        let is_selected_root =
                            self.selected_machine == idx && self.active_view == ViewKind::Overview;
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(is_selected_root, machine.sidebar_title())
                                .clicked()
                            {
                                switch_to = Some((idx, ViewKind::Overview));
                            }
                            if !machine.is_local && ui.small_button("Disconnect").clicked() {
                                disconnect_target = Some(idx);
                            }
                        });

                        ui.indent(format!("machine_children_{idx}"), |ui| {
                            let disabled_count =
                                machine.users.iter().filter(|u| u.is_disabled()).count();
                            let users_label = if disabled_count > 0 {
                                format!(
                                    "Users ({}, {} disabled)",
                                    machine.users.len(),
                                    disabled_count
                                )
                            } else {
                                format!("Users ({})", machine.users.len())
                            };
                            let groups_label = format!("Groups ({})", machine.groups.len());
                            let builtin_label =
                                format!("Built-in Principals ({})", machine.builtins.len());

                            let nodes = [
                                (ViewKind::Users, users_label),
                                (ViewKind::Groups, groups_label),
                                (ViewKind::BuiltIn, builtin_label),
                            ];

                            for (view, label) in nodes {
                                let selected =
                                    self.selected_machine == idx && self.active_view == view;
                                if ui.selectable_label(selected, label).clicked() {
                                    switch_to = Some((idx, view));
                                }
                            }
                        });
                        ui.add_space(6.0_f32);
                    }
                });

                if let Some((idx, view)) = switch_to {
                    if self.selected_machine != idx || self.active_view != view {
                        self.selected_machine = idx;
                        self.active_view = view;
                        self.selected_items.clear();
                        self.sort_column = SortColumn::Name;
                        self.sort_ascending = true;
                    }
                }

                if let Some(idx) = disconnect_target {
                    if self.config.warn_disconnect {
                        let name = self.machines[idx].display_name.clone();
                        self.dialog = Some(ActiveDialog::ConfirmDisconnect {
                            machine_idx: idx,
                            host: name,
                        });
                    } else {
                        self.disconnect_machine(idx);
                    }
                }
            });
    }

    /// Renders the bottom status bar and contextual action buttons.
    fn render_bottom_bar(&mut self, ctx: &egui::Context, palette: Palette) {
        egui::TopBottomPanel::bottom("status_footer")
            .frame(
                Frame::NONE
                    .fill(palette.bg_panel)
                    .inner_margin(Margin::symmetric(12, 6))
                    .stroke(Stroke::new(1.0_f32, palette.border)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let machine = self.current_machine();
                    let total = match self.active_view {
                        ViewKind::Overview => 3,
                        ViewKind::Users => machine.users.len(),
                        ViewKind::Groups => machine.groups.len(),
                        ViewKind::BuiltIn => machine.builtins.len(),
                    };
                    let selected_count = self.selected_items.len();
                    let summary = if selected_count > 0 {
                        format!("{total} elements ({selected_count} selected)")
                    } else {
                        format!("{total} elements")
                    };
                    ui.label(RichText::new(summary).color(palette.text_muted));

                    if let Some(notice) = &self.notice {
                        ui.separator();
                        let color = match notice.kind {
                            NoticeKind::Info => palette.text_primary,
                            NoticeKind::Warning => palette.warning,
                            NoticeKind::Error => palette.danger,
                        };
                        ui.label(RichText::new(&notice.text).color(color));
                    }
                });
            });
    }

    /// Renders the main workspace panel (action strip, Quick Search, and data table).
    fn render_main_content(&mut self, ctx: &egui::Context, palette: Palette) {
        egui::CentralPanel::default()
            .frame(
                Frame::NONE
                    .fill(palette.bg_canvas)
                    .inner_margin(Margin::symmetric(14, 10)),
            )
            .show(ctx, |ui| {
                self.render_view_header(ui, palette);
                ui.add_space(8.0_f32);

                match self.active_view {
                    ViewKind::Overview => self.render_overview_table(ui, palette),
                    ViewKind::Users => self.render_users_table(ui, palette),
                    ViewKind::Groups => self.render_groups_table(ui, palette),
                    ViewKind::BuiltIn => self.render_builtin_table(ui, palette),
                }
            });
    }

    /// Renders the view title, contextual action buttons, and live Quick Search bar.
    fn render_view_header(&mut self, ui: &mut Ui, palette: Palette) {
        let machine_name = self.current_machine().display_name.clone();
        let single_selected = if self.selected_items.len() == 1 {
            self.selected_items.iter().next().cloned()
        } else {
            None
        };
        let any_selected = !self.selected_items.is_empty();

        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{machine_name} / {}", self.active_view.label()))
                    .strong()
                    .color(palette.text_primary),
            );

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !self.quick_search.is_empty() && ui.button("Clear").clicked() {
                    self.quick_search.clear();
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.quick_search)
                        .desired_width(240.0_f32)
                        .hint_text("Quick filter..."),
                );
            });
        });

        ui.add_space(6.0_f32);

        ui.horizontal(|ui| match self.active_view {
            ViewKind::Users => {
                if ui.button("Add User...").clicked() {
                    let groups: Vec<String> = self
                        .current_machine()
                        .groups
                        .iter()
                        .map(|g| g.name.clone())
                        .collect();
                    self.dialog =
                        Some(dialogs::make_add_user_dialog(self.selected_machine, groups));
                }
                if ui
                    .add_enabled(single_selected.is_some(), egui::Button::new("Edit..."))
                    .clicked()
                {
                    if let Some(name) = single_selected.clone() {
                        self.open_edit_user(self.selected_machine, &name);
                    }
                }
                if ui
                    .add_enabled(
                        single_selected.is_some(),
                        egui::Button::new("Set Password..."),
                    )
                    .clicked()
                {
                    if let Some(name) = single_selected.clone() {
                        self.dialog = Some(dialogs::make_set_password_dialog(
                            self.selected_machine,
                            name,
                        ));
                    }
                }
                if ui
                    .add_enabled(single_selected.is_some(), egui::Button::new("Rename..."))
                    .clicked()
                {
                    if let Some(name) = single_selected.clone() {
                        self.dialog = Some(dialogs::make_rename_dialog(
                            self.selected_machine,
                            true,
                            name,
                        ));
                    }
                }
                if ui
                    .add_enabled(any_selected, egui::Button::new("Delete"))
                    .clicked()
                {
                    self.request_delete_selected();
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let disabled_total = self
                        .current_machine()
                        .users
                        .iter()
                        .filter(|u| u.is_disabled())
                        .count();
                    ui.label(
                        RichText::new(format!("Disabled accounts: {disabled_total}"))
                            .small()
                            .color(palette.text_muted),
                    );
                    draw_user_icon_inline(ui, true, palette);
                });
            }
            ViewKind::Groups => {
                if ui.button("Add Group...").clicked() {
                    self.dialog = Some(dialogs::make_add_group_dialog(self.selected_machine));
                }
                if ui
                    .add_enabled(single_selected.is_some(), egui::Button::new("Edit..."))
                    .clicked()
                {
                    if let Some(name) = single_selected.clone() {
                        self.open_edit_group(self.selected_machine, &name);
                    }
                }
                if ui
                    .add_enabled(single_selected.is_some(), egui::Button::new("Rename..."))
                    .clicked()
                {
                    if let Some(name) = single_selected.clone() {
                        self.dialog = Some(dialogs::make_rename_dialog(
                            self.selected_machine,
                            false,
                            name,
                        ));
                    }
                }
                if ui
                    .add_enabled(any_selected, egui::Button::new("Delete"))
                    .clicked()
                {
                    self.request_delete_selected();
                }
            }
            ViewKind::BuiltIn => {
                if ui
                    .add_enabled(single_selected.is_some(), egui::Button::new("Details..."))
                    .clicked()
                {
                    if let Some(sid) = single_selected.clone() {
                        if let Some(item) = self
                            .current_machine()
                            .builtins
                            .iter()
                            .find(|b| b.sid == sid)
                            .cloned()
                        {
                            self.dialog = Some(ActiveDialog::BuiltInDetails(item));
                        }
                    }
                }
                if ui
                    .add_enabled(single_selected.is_some(), egui::Button::new("Copy SID"))
                    .clicked()
                {
                    if let Some(sid) = single_selected {
                        ui.ctx().copy_text(sid.clone());
                        self.set_notice(NoticeKind::Info, format!("Copied SID {sid}."));
                    }
                }
            }
            ViewKind::Overview => {
                ui.label(
                    RichText::new("Double-click or click a category below to open it.")
                        .color(palette.text_muted),
                );
            }
        });
    }

    /// Renders the machine root overview listing Users, Groups, and Built-in Security Principals.
    fn render_overview_table(&mut self, ui: &mut Ui, palette: Palette) {
        let machine = self.current_machine();
        let rows = [
            (
                ViewKind::Users,
                "Users",
                format!(
                    "{} local accounts ({} disabled)",
                    machine.users.len(),
                    machine.users.iter().filter(|u| u.is_disabled()).count()
                ),
            ),
            (
                ViewKind::Groups,
                "Groups",
                format!("{} local security groups", machine.groups.len()),
            ),
            (
                ViewKind::BuiltIn,
                "Built-in Security Principals",
                format!(
                    "{} well-known Windows security principals",
                    machine.builtins.len()
                ),
            ),
        ];

        let mut open_view = None;
        Frame::NONE
            .stroke(Stroke::new(1.0_f32, palette.border))
            .corner_radius(CornerRadius::same(4))
            .show(ui, |ui| {
                for (i, (kind, title, desc)) in rows.iter().enumerate() {
                    let bg = if i % 2 == 1 {
                        palette.row_alt
                    } else {
                        palette.bg_canvas
                    };
                    Frame::NONE
                        .fill(bg)
                        .inner_margin(Margin::symmetric(12, 10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                match kind {
                                    ViewKind::Users => draw_user_icon_inline(ui, false, palette),
                                    ViewKind::Groups => draw_group_icon_inline(ui, palette),
                                    ViewKind::BuiltIn => draw_builtin_icon_inline(ui, palette),
                                    ViewKind::Overview => {}
                                }
                                if ui.button(*title).clicked() {
                                    open_view = Some(*kind);
                                }
                                ui.label(RichText::new(desc).color(palette.text_muted));
                            });
                        });
                }
            });

        if let Some(view) = open_view {
            self.active_view = view;
            self.selected_items.clear();
        }
    }

    /// Renders the Users table with red disabled-user badges, sorting, and multi-select.
    fn render_users_table(&mut self, ui: &mut Ui, palette: Palette) {
        let filter = self.quick_search.trim().to_lowercase();
        let show_sid = self.config.show_sid_in_users;
        let mut users: Vec<UserAccount> = self
            .current_machine()
            .users
            .iter()
            .filter(|u| {
                filter.is_empty()
                    || u.name.to_lowercase().contains(&filter)
                    || u.full_name.to_lowercase().contains(&filter)
                    || u.comment.to_lowercase().contains(&filter)
                    || u.status_label().to_lowercase().contains(&filter)
                    || u.sid.to_lowercase().contains(&filter)
            })
            .cloned()
            .collect();

        users.sort_by(|a, b| {
            let ord = match self.sort_column {
                SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SortColumn::Secondary => {
                    a.full_name.to_lowercase().cmp(&b.full_name.to_lowercase())
                }
                SortColumn::Status => a.status_label().cmp(b.status_label()),
                SortColumn::Detail => a.comment.to_lowercase().cmp(&b.comment.to_lowercase()),
            };
            if self.sort_ascending {
                ord
            } else {
                ord.reverse()
            }
        });

        let mut edit_user: Option<String> = None;
        let mut set_pw_user: Option<String> = None;
        let mut rename_user: Option<String> = None;
        let mut delete_user: Option<String> = None;
        let mut toggle_disable: Option<(String, bool)> = None;

        Frame::NONE
            .stroke(Stroke::new(1.0_f32, palette.border))
            .corner_radius(CornerRadius::same(4))
            .show(ui, |ui| {
                let avail_w = ui.available_width();
                let name_w = (avail_w * 0.22_f32).clamp(160.0_f32, 260.0_f32);
                let full_w = (avail_w * 0.18_f32).clamp(130.0_f32, 220.0_f32);
                let status_w = 130.0_f32;
                let sid_w = if show_sid { 240.0_f32 } else { 0.0_f32 };

                // Header bar
                Frame::NONE
                    .fill(palette.bg_surface)
                    .inner_margin(Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            self.sort_header(ui, "Name", SortColumn::Name, name_w, palette);
                            self.sort_header(
                                ui,
                                "Full Name",
                                SortColumn::Secondary,
                                full_w,
                                palette,
                            );
                            self.sort_header(ui, "Status", SortColumn::Status, status_w, palette);
                            if show_sid {
                                fixed_cell(ui, sid_w, 24.0_f32, |ui| {
                                    ui.label(RichText::new("SID").strong());
                                });
                            }
                            self.sort_header(
                                ui,
                                "Description",
                                SortColumn::Detail,
                                ui.available_width().max(120.0_f32),
                                palette,
                            );
                        });
                    });

                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if users.is_empty() {
                            ui.add_space(16.0_f32);
                            ui.centered_and_justified(|ui| {
                                ui.label(
                                    RichText::new("No user accounts match the current filter.")
                                        .color(palette.text_muted),
                                );
                            });
                            return;
                        }

                        for (idx, user) in users.iter().enumerate() {
                            let is_selected = self.selected_items.contains(&user.name);
                            let row_bg = if is_selected {
                                palette.row_selected
                            } else if idx % 2 == 1 {
                                palette.row_alt
                            } else {
                                palette.bg_canvas
                            };

                            let resp = Frame::NONE
                                .fill(row_bg)
                                .inner_margin(Margin::symmetric(10, 5))
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        fixed_cell(ui, name_w, 24.0_f32, |ui| {
                                            draw_user_icon_inline(ui, user.is_disabled(), palette);
                                            let name_color = if user.is_disabled() {
                                                palette.text_muted
                                            } else {
                                                palette.text_primary
                                            };
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&user.name).color(name_color),
                                                )
                                                .truncate()
                                                .selectable(false),
                                            );
                                        });

                                        fixed_cell(ui, full_w, 24.0_f32, |ui| {
                                            ui.add(
                                                egui::Label::new(&user.full_name)
                                                    .truncate()
                                                    .selectable(false),
                                            );
                                        });

                                        fixed_cell(ui, status_w, 24.0_f32, |ui| {
                                            let status_color = if user.is_disabled() {
                                                palette.danger
                                            } else if user.is_locked_out() {
                                                palette.warning
                                            } else {
                                                palette.success
                                            };
                                            ui.label(
                                                RichText::new(user.status_label())
                                                    .color(status_color),
                                            );
                                        });

                                        if show_sid {
                                            fixed_cell(ui, sid_w, 24.0_f32, |ui| {
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(&user.sid)
                                                            .small()
                                                            .color(palette.text_muted),
                                                    )
                                                    .truncate()
                                                    .selectable(false),
                                                );
                                            });
                                        }

                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&user.comment)
                                                    .color(palette.text_muted),
                                            )
                                            .truncate()
                                            .selectable(false),
                                        );
                                    });
                                })
                                .response
                                .interact(Sense::click());

                            if resp.clicked() {
                                let ctrl = ui.input(|i| i.modifiers.ctrl || i.modifiers.command);
                                if ctrl {
                                    if is_selected {
                                        self.selected_items.remove(&user.name);
                                    } else {
                                        self.selected_items.insert(user.name.clone());
                                    }
                                } else {
                                    self.selected_items.clear();
                                    self.selected_items.insert(user.name.clone());
                                }
                            }
                            if resp.double_clicked() {
                                self.selected_items.clear();
                                self.selected_items.insert(user.name.clone());
                                edit_user = Some(user.name.clone());
                            }
                            resp.context_menu(|ui| {
                                if ui.button("Edit Properties...").clicked() {
                                    edit_user = Some(user.name.clone());
                                    ui.close_menu();
                                }
                                if ui.button("Set Password...").clicked() {
                                    set_pw_user = Some(user.name.clone());
                                    ui.close_menu();
                                }
                                let toggle_label = if user.is_disabled() {
                                    "Enable Account"
                                } else {
                                    "Disable Account"
                                };
                                if ui.button(toggle_label).clicked() {
                                    toggle_disable = Some((user.name.clone(), !user.is_disabled()));
                                    ui.close_menu();
                                }
                                if ui.button("Rename...").clicked() {
                                    rename_user = Some(user.name.clone());
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("Delete").clicked() {
                                    delete_user = Some(user.name.clone());
                                    ui.close_menu();
                                }
                            });
                        }
                    });
            });

        if let Some(name) = edit_user {
            self.open_edit_user(self.selected_machine, &name);
        } else if let Some(name) = set_pw_user {
            self.dialog = Some(dialogs::make_set_password_dialog(
                self.selected_machine,
                name,
            ));
        } else if let Some(name) = rename_user {
            self.dialog = Some(dialogs::make_rename_dialog(
                self.selected_machine,
                true,
                name,
            ));
        } else if let Some(name) = delete_user {
            self.selected_items.clear();
            self.selected_items.insert(name);
            self.request_delete_selected();
        } else if let Some((name, disable)) = toggle_disable {
            self.quick_toggle_user_disabled(self.selected_machine, &name, disable);
        }
    }

    /// Toggles the UF_ACCOUNTDISABLE flag on a user account from the context menu.
    fn quick_toggle_user_disabled(&mut self, machine_idx: usize, username: &str, disable: bool) {
        let Some(machine) = self.machines.get(machine_idx) else {
            return;
        };
        let target = machine.server_target.clone();
        let detail = match self.backend.get_user(target.as_deref(), username) {
            Ok(user) => user,
            Err(err) => {
                self.set_notice(NoticeKind::Error, err.to_string());
                return;
            }
        };
        let mut new_flags = detail.flags;
        if disable {
            new_flags |= crate::model::user_flags::UF_ACCOUNTDISABLE;
        } else {
            new_flags &= !crate::model::user_flags::UF_ACCOUNTDISABLE;
        }
        let req = crate::model::UserUpdateRequest {
            name: detail.name,
            full_name: detail.full_name,
            comment: detail.comment,
            flags: new_flags,
            password_expired: detail.password_expired,
            acct_expires: detail.acct_expires,
            profile: detail.profile,
            script_path: detail.script_path,
            home_dir: detail.home_dir,
            home_dir_drive: detail.home_dir_drive,
            logon_hours: detail.logon_hours,
        };
        match self.backend.update_user(target.as_deref(), &req) {
            Ok(()) => {
                self.refresh_machine(machine_idx);
                let action = if disable { "Disabled" } else { "Enabled" };
                self.set_notice(NoticeKind::Info, format!("{action} user '{username}'."));
            }
            Err(err) => self.set_notice(NoticeKind::Error, err.to_string()),
        }
    }

    /// Renders the Groups table with sorting, multi-select, and context menu.
    fn render_groups_table(&mut self, ui: &mut Ui, palette: Palette) {
        let filter = self.quick_search.trim().to_lowercase();
        let mut groups: Vec<GroupAccount> = self
            .current_machine()
            .groups
            .iter()
            .filter(|g| {
                filter.is_empty()
                    || g.name.to_lowercase().contains(&filter)
                    || g.comment.to_lowercase().contains(&filter)
            })
            .cloned()
            .collect();

        groups.sort_by(|a, b| {
            let ord = match self.sort_column {
                SortColumn::Detail => a.comment.to_lowercase().cmp(&b.comment.to_lowercase()),
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            };
            if self.sort_ascending {
                ord
            } else {
                ord.reverse()
            }
        });

        let mut edit_group: Option<String> = None;
        let mut rename_group: Option<String> = None;
        let mut delete_group: Option<String> = None;

        Frame::NONE
            .stroke(Stroke::new(1.0_f32, palette.border))
            .corner_radius(CornerRadius::same(4))
            .show(ui, |ui| {
                let name_w = (ui.available_width() * 0.30_f32).clamp(210.0_f32, 340.0_f32);

                Frame::NONE
                    .fill(palette.bg_surface)
                    .inner_margin(Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            self.sort_header(ui, "Group Name", SortColumn::Name, name_w, palette);
                            self.sort_header(
                                ui,
                                "Description",
                                SortColumn::Detail,
                                ui.available_width().max(160.0_f32),
                                palette,
                            );
                        });
                    });

                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if groups.is_empty() {
                            ui.add_space(16.0_f32);
                            ui.centered_and_justified(|ui| {
                                ui.label(
                                    RichText::new("No local groups match the current filter.")
                                        .color(palette.text_muted),
                                );
                            });
                            return;
                        }

                        for (idx, group) in groups.iter().enumerate() {
                            let is_selected = self.selected_items.contains(&group.name);
                            let row_bg = if is_selected {
                                palette.row_selected
                            } else if idx % 2 == 1 {
                                palette.row_alt
                            } else {
                                palette.bg_canvas
                            };

                            let resp = Frame::NONE
                                .fill(row_bg)
                                .inner_margin(Margin::symmetric(10, 5))
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        fixed_cell(ui, name_w, 24.0_f32, |ui| {
                                            draw_group_icon_inline(ui, palette);
                                            ui.add(
                                                egui::Label::new(&group.name)
                                                    .truncate()
                                                    .selectable(false),
                                            );
                                        });
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&group.comment)
                                                    .color(palette.text_muted),
                                            )
                                            .truncate()
                                            .selectable(false),
                                        );
                                    });
                                })
                                .response
                                .interact(Sense::click());

                            if resp.clicked() {
                                let ctrl = ui.input(|i| i.modifiers.ctrl || i.modifiers.command);
                                if ctrl {
                                    if is_selected {
                                        self.selected_items.remove(&group.name);
                                    } else {
                                        self.selected_items.insert(group.name.clone());
                                    }
                                } else {
                                    self.selected_items.clear();
                                    self.selected_items.insert(group.name.clone());
                                }
                            }
                            if resp.double_clicked() {
                                self.selected_items.clear();
                                self.selected_items.insert(group.name.clone());
                                edit_group = Some(group.name.clone());
                            }
                            resp.context_menu(|ui| {
                                if ui.button("Edit Members & Description...").clicked() {
                                    edit_group = Some(group.name.clone());
                                    ui.close_menu();
                                }
                                if ui.button("Rename...").clicked() {
                                    rename_group = Some(group.name.clone());
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui.button("Delete").clicked() {
                                    delete_group = Some(group.name.clone());
                                    ui.close_menu();
                                }
                            });
                        }
                    });
            });

        if let Some(name) = edit_group {
            self.open_edit_group(self.selected_machine, &name);
        } else if let Some(name) = rename_group {
            self.dialog = Some(dialogs::make_rename_dialog(
                self.selected_machine,
                false,
                name,
            ));
        } else if let Some(name) = delete_group {
            self.selected_items.clear();
            self.selected_items.insert(name);
            self.request_delete_selected();
        }
    }

    /// Renders the Built-in Security Principals table sorted numerically by SID.
    fn render_builtin_table(&mut self, ui: &mut Ui, palette: Palette) {
        let filter = self.quick_search.trim().to_lowercase();
        let mut items: Vec<BuiltInPrincipal> = self
            .current_machine()
            .builtins
            .iter()
            .filter(|b| {
                filter.is_empty()
                    || b.name.to_lowercase().contains(&filter)
                    || b.domain.to_lowercase().contains(&filter)
                    || b.sid.to_lowercase().contains(&filter)
            })
            .cloned()
            .collect();

        items.sort_by(|a, b| {
            let ord = match self.sort_column {
                SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SortColumn::Secondary => a.domain.to_lowercase().cmp(&b.domain.to_lowercase()),
                _ => compare_sids(&a.sid, &b.sid),
            };
            if self.sort_ascending {
                ord
            } else {
                ord.reverse()
            }
        });

        let mut open_detail: Option<BuiltInPrincipal> = None;

        Frame::NONE
            .stroke(Stroke::new(1.0_f32, palette.border))
            .corner_radius(CornerRadius::same(4))
            .show(ui, |ui| {
                let avail_w = ui.available_width();
                let name_w = (avail_w * 0.36_f32).clamp(220.0_f32, 360.0_f32);
                let domain_w = (avail_w * 0.24_f32).clamp(150.0_f32, 240.0_f32);

                Frame::NONE
                    .fill(palette.bg_surface)
                    .inner_margin(Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            self.sort_header(
                                ui,
                                "Principal Name",
                                SortColumn::Name,
                                name_w,
                                palette,
                            );
                            self.sort_header(
                                ui,
                                "Authority",
                                SortColumn::Secondary,
                                domain_w,
                                palette,
                            );
                            self.sort_header(
                                ui,
                                "SID",
                                SortColumn::Detail,
                                ui.available_width().max(180.0_f32),
                                palette,
                            );
                        });
                    });

                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (idx, item) in items.iter().enumerate() {
                            let is_selected = self.selected_items.contains(&item.sid);
                            let row_bg = if is_selected {
                                palette.row_selected
                            } else if idx % 2 == 1 {
                                palette.row_alt
                            } else {
                                palette.bg_canvas
                            };

                            let resp = Frame::NONE
                                .fill(row_bg)
                                .inner_margin(Margin::symmetric(10, 5))
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        fixed_cell(ui, name_w, 24.0_f32, |ui| {
                                            draw_builtin_icon_inline(ui, palette);
                                            ui.add(
                                                egui::Label::new(&item.name)
                                                    .truncate()
                                                    .selectable(false),
                                            );
                                        });
                                        fixed_cell(ui, domain_w, 24.0_f32, |ui| {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&item.domain)
                                                        .color(palette.text_muted),
                                                )
                                                .truncate()
                                                .selectable(false),
                                            );
                                        });
                                        ui.add(
                                            egui::Label::new(&item.sid)
                                                .truncate()
                                                .selectable(false),
                                        );
                                    });
                                })
                                .response
                                .interact(Sense::click());

                            if resp.clicked() {
                                self.selected_items.clear();
                                self.selected_items.insert(item.sid.clone());
                            }
                            if resp.double_clicked() {
                                self.selected_items.clear();
                                self.selected_items.insert(item.sid.clone());
                                open_detail = Some(item.clone());
                            }
                            resp.context_menu(|ui| {
                                if ui.button("Details...").clicked() {
                                    open_detail = Some(item.clone());
                                    ui.close_menu();
                                }
                                if ui.button("Copy Name").clicked() {
                                    ui.ctx().copy_text(item.name.clone());
                                    ui.close_menu();
                                }
                                if ui.button("Copy SID").clicked() {
                                    ui.ctx().copy_text(item.sid.clone());
                                    ui.close_menu();
                                }
                            });
                        }
                    });
            });

        if let Some(item) = open_detail {
            self.dialog = Some(ActiveDialog::BuiltInDetails(item));
        }
    }

    /// Renders a clickable sortable column header with a custom vector sort triangle.
    fn sort_header(
        &mut self,
        ui: &mut Ui,
        label: &str,
        col: SortColumn,
        width: f32,
        palette: Palette,
    ) {
        let is_active = self.sort_column == col;
        let ascending = self.sort_ascending;
        fixed_cell(ui, width, 24.0_f32, |ui| {
            let clicked = ui
                .selectable_label(false, RichText::new(label).strong())
                .clicked();
            if is_active {
                let (tri_rect, _) =
                    ui.allocate_exact_size(Vec2::new(10.0_f32, 10.0_f32), Sense::hover());
                let c = tri_rect.center();
                let pts = if ascending {
                    vec![
                        Pos2::new(c.x, c.y - 3.0_f32),
                        Pos2::new(c.x + 4.0_f32, c.y + 3.0_f32),
                        Pos2::new(c.x - 4.0_f32, c.y + 3.0_f32),
                    ]
                } else {
                    vec![
                        Pos2::new(c.x - 4.0_f32, c.y - 3.0_f32),
                        Pos2::new(c.x + 4.0_f32, c.y - 3.0_f32),
                        Pos2::new(c.x, c.y + 3.0_f32),
                    ]
                };
                ui.painter().add(egui::Shape::convex_polygon(
                    pts,
                    palette.accent,
                    Stroke::NONE,
                ));
            }
            if clicked {
                if is_active {
                    self.sort_ascending = !self.sort_ascending;
                } else {
                    self.sort_column = col;
                    self.sort_ascending = true;
                }
            }
        });
    }
}

/// Allocates a strict fixed-width horizontal table cell so headers and rows align cleanly.
fn fixed_cell(ui: &mut Ui, width: f32, height: f32, add_contents: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(
        Vec2::new(width, height),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.set_min_size(Vec2::new(width, height));
            ui.set_max_width(width);
            add_contents(ui);
        },
    );
}

impl Default for AccountManagerApp {
    fn default() -> Self {
        Self::new()
    }
}

impl eframe::App for AccountManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_theme_and_fonts(ctx);
        let palette = Palette::for_theme(self.config.theme);

        // Keyboard shortcuts: F5 to refresh, Ctrl+F for Global Search.
        if ctx.input(|i| i.key_pressed(egui::Key::F5)) {
            self.refresh_machine(self.selected_machine);
            self.set_notice(NoticeKind::Info, "Refreshed account lists.");
        }
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::F)) {
            self.dialog = Some(dialogs::make_global_search_dialog());
        }

        self.render_top_bar(ctx, palette);
        self.render_bottom_bar(ctx, palette);
        self.render_sidebar(ctx, palette);
        self.render_main_content(ctx, palette);
        self.render_active_dialog(ctx, palette);
    }
}

/// Paints a crisp user silhouette icon with a high-contrast red disabled badge when disabled.
pub fn draw_user_icon_inline(ui: &mut Ui, is_disabled: bool, palette: Palette) {
    let size = Vec2::new(22.0_f32, 22.0_f32);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let painter = ui.painter();

    let body_color = if is_disabled {
        palette.text_muted
    } else {
        palette.accent
    };

    let head_center = Pos2::new(rect.center().x - 1.0_f32, rect.top() + 6.5_f32);
    painter.circle_filled(head_center, 4.0_f32, body_color);

    let shoulder_rect = Rect::from_min_max(
        Pos2::new(rect.left() + 2.5_f32, rect.top() + 12.0_f32),
        Pos2::new(rect.right() - 4.5_f32, rect.bottom() - 2.0_f32),
    );
    painter.rect_filled(shoulder_rect, CornerRadius::same(4), body_color);

    if is_disabled {
        // Issue #7 red circular disabled-state badge with crisp white downward indicator.
        let badge_center = Pos2::new(rect.right() - 5.2_f32, rect.bottom() - 5.2_f32);
        let badge_radius = 5.2_f32;
        painter.circle_filled(badge_center, badge_radius, palette.danger);
        painter.circle_stroke(
            badge_center,
            badge_radius,
            Stroke::new(1.0_f32, palette.bg_canvas),
        );

        let white = Color32::WHITE;
        painter.line_segment(
            [
                Pos2::new(badge_center.x, badge_center.y - 2.6_f32),
                Pos2::new(badge_center.x, badge_center.y + 2.0_f32),
            ],
            Stroke::new(1.6_f32, white),
        );
        painter.line_segment(
            [
                Pos2::new(badge_center.x - 2.3_f32, badge_center.y + 0.1_f32),
                Pos2::new(badge_center.x, badge_center.y + 2.4_f32),
            ],
            Stroke::new(1.5_f32, white),
        );
        painter.line_segment(
            [
                Pos2::new(badge_center.x + 2.3_f32, badge_center.y + 0.1_f32),
                Pos2::new(badge_center.x, badge_center.y + 2.4_f32),
            ],
            Stroke::new(1.5_f32, white),
        );
    }
}

/// Paints a dual-silhouette icon representing a local security group.
pub fn draw_group_icon_inline(ui: &mut Ui, palette: Palette) {
    let size = Vec2::new(22.0_f32, 22.0_f32);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let painter = ui.painter();
    let back_color = palette.text_muted;
    let front_color = palette.success;

    // Secondary person silhouette behind and to the right.
    painter.circle_filled(
        Pos2::new(rect.right() - 6.5_f32, rect.top() + 7.0_f32),
        3.2_f32,
        back_color,
    );
    painter.rect_filled(
        Rect::from_min_max(
            Pos2::new(rect.center().x - 1.0_f32, rect.top() + 11.5_f32),
            Pos2::new(rect.right() - 1.5_f32, rect.bottom() - 2.5_f32),
        ),
        CornerRadius::same(3),
        back_color,
    );

    // Primary person silhouette in foreground.
    painter.circle_filled(
        Pos2::new(rect.left() + 7.5_f32, rect.top() + 6.5_f32),
        3.8_f32,
        front_color,
    );
    painter.rect_filled(
        Rect::from_min_max(
            Pos2::new(rect.left() + 2.0_f32, rect.top() + 11.5_f32),
            Pos2::new(rect.left() + 13.5_f32, rect.bottom() - 2.0_f32),
        ),
        CornerRadius::same(3),
        front_color,
    );
}

/// Paints a shield icon representing a built-in well-known security principal.
pub fn draw_builtin_icon_inline(ui: &mut Ui, palette: Palette) {
    let size = Vec2::new(22.0_f32, 22.0_f32);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let painter = ui.painter();
    let c = rect.center();
    let pts = vec![
        Pos2::new(c.x, rect.top() + 2.5_f32),
        Pos2::new(rect.right() - 3.5_f32, rect.top() + 5.5_f32),
        Pos2::new(rect.right() - 4.5_f32, rect.bottom() - 7.0_f32),
        Pos2::new(c.x, rect.bottom() - 2.0_f32),
        Pos2::new(rect.left() + 4.5_f32, rect.bottom() - 7.0_f32),
        Pos2::new(rect.left() + 3.5_f32, rect.top() + 5.5_f32),
    ];
    painter.add(egui::Shape::convex_polygon(
        pts,
        palette.accent.gamma_multiply(0.25_f32),
        Stroke::new(1.5_f32, palette.accent),
    ));
}

/// Paints the icon matching a group member's type and local disabled state.
pub fn draw_member_icon_inline(ui: &mut Ui, member: &GroupMember, palette: Palette) {
    match member.kind {
        crate::model::MemberKind::User => {
            draw_user_icon_inline(ui, member.is_disabled.unwrap_or(false), palette);
        }
        crate::model::MemberKind::Group | crate::model::MemberKind::Alias => {
            draw_group_icon_inline(ui, palette);
        }
        _ => {
            draw_builtin_icon_inline(ui, palette);
        }
    }
}

/// Starts the eframe native desktop window for Local User and Group Management.
pub fn run_gui() -> Result<(), String> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Local User and Group Management")
        .with_inner_size([1180.0_f32, 740.0_f32])
        .with_min_inner_size([860.0_f32, 560.0_f32]);

    if let Some(icon) = load_viewport_icon() {
        viewport = viewport.with_icon(icon);
    }

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Local User and Group Management",
        native_options,
        Box::new(|_cc| Ok(Box::new(AccountManagerApp::new()))),
    )
    .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typography_scale_is_one_point_five_x() {
        assert!((FONT_SCALE - 1.5_f32).abs() < f32::EPSILON);
    }

    #[test]
    fn embedded_icon_decodes_with_transparent_corners() {
        let (rgba, w, h) = load_app_icon_rgba().expect("embedded icon PNG must decode");
        assert_eq!((w, h), (256, 256));
        assert_eq!(rgba.len(), 256 * 256 * 4);
        assert_eq!(rgba[3], 0, "top-left corner must be transparent");
        let last_alpha = rgba[rgba.len() - 1];
        assert_eq!(last_alpha, 0, "bottom-right corner must be transparent");
    }

    #[test]
    fn palettes_keep_clean_light_and_dark_surfaces() {
        let light = Palette::for_theme(ThemeMode::Light);
        let dark = Palette::for_theme(ThemeMode::Dark);
        assert_eq!(light.bg_canvas, Color32::from_rgb(255, 255, 255));
        assert!(dark.bg_canvas.r() < 40);
        assert_eq!(light.danger, dark.danger);
    }
}
