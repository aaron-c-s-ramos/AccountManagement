//! Modal dialogs for user, group, password, remote connection, and search workflows.

use eframe::egui::{
    self, Align, CornerRadius, Frame, Grid, Layout, Margin, RichText, ScrollArea, Sense, Stroke,
    Ui, Vec2,
};

use crate::cli::APP_VERSION;
use crate::gui::{
    draw_builtin_icon_inline, draw_group_icon_inline, draw_member_icon_inline,
    draw_user_icon_inline, AccountManagerApp, NoticeKind, Palette, ViewKind,
};
use crate::model::{
    parse_expiration_date, user_flags, validate_group_name, validate_username, BuiltInPrincipal,
    GroupAccount, GroupMember, LogonHours, NewUserRequest, UserAccount, UserUpdateRequest,
    TIMEQ_FOREVER,
};
use crate::winapi::AccountBackend;

/// Active tab inside the Edit User modal dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditUserTab {
    /// Identity, flags, expiration, and logon status.
    General,
    /// Local group memberships.
    MemberOf,
    /// Profile path, logon script, and home folder.
    Profile,
    /// Interactive 7x24 weekly logon hours matrix.
    LogonHours,
}

/// Active modal dialog variant.
#[derive(Debug, Clone)]
pub enum ActiveDialog {
    /// Create a new local user account.
    AddUser {
        machine_idx: usize,
        username: String,
        full_name: String,
        description: String,
        password: String,
        confirm_password: String,
        must_change_pw: bool,
        cannot_change_pw: bool,
        pw_never_expires: bool,
        account_disabled: bool,
        show_advanced: bool,
        profile: String,
        script_path: String,
        home_dir: String,
        home_dir_drive: String,
        available_groups: Vec<String>,
        selected_groups: Vec<String>,
        error: Option<String>,
    },
    /// Edit an existing local user account.
    EditUser {
        machine_idx: usize,
        tab: EditUserTab,
        user: UserAccount,
        must_change_pw: bool,
        cannot_change_pw: bool,
        pw_never_expires: bool,
        pw_not_required: bool,
        account_disabled: bool,
        account_locked: bool,
        smartcard_required: bool,
        expires_enabled: bool,
        expires_date_text: String,
        member_groups: Vec<String>,
        add_group_pick: String,
        error: Option<String>,
    },
    /// Set or reset a user password.
    SetPassword {
        machine_idx: usize,
        username: String,
        password: String,
        confirm_password: String,
        error: Option<String>,
    },
    /// Create a new local security group.
    AddGroup {
        machine_idx: usize,
        name: String,
        description: String,
        error: Option<String>,
    },
    /// Edit a local group's description and membership roster.
    EditGroup {
        machine_idx: usize,
        group: GroupAccount,
        members: Vec<GroupMember>,
        picker_filter: String,
        manual_member: String,
        error: Option<String>,
    },
    /// Rename an existing user or local group.
    Rename {
        machine_idx: usize,
        is_user: bool,
        old_name: String,
        new_name: String,
        error: Option<String>,
    },
    /// Confirm deletion of one or more users or groups.
    ConfirmDelete {
        machine_idx: usize,
        is_user: bool,
        names: Vec<String>,
    },
    /// Confirm disconnecting from a remote computer.
    ConfirmDisconnect { machine_idx: usize, host: String },
    /// Connect to a remote Windows computer via WNet and NetAPI32.
    ConnectRemote {
        host: String,
        use_credentials: bool,
        username: String,
        password: String,
        recent_hosts: Vec<String>,
        error: Option<String>,
    },
    /// Search across current or all connected computers.
    GlobalSearch {
        query: String,
        all_machines: bool,
        include_users: bool,
        include_groups: bool,
        include_builtin: bool,
    },
    /// Inspect and copy properties of a built-in well-known security principal.
    BuiltInDetails(BuiltInPrincipal),
    /// Configure warning prompts, table columns, and default theme.
    Settings,
    /// Show version, license, credits, and repository links.
    About,
}

/// Builds a fresh Add User dialog with "Users" pre-selected when present.
pub fn make_add_user_dialog(machine_idx: usize, available_groups: Vec<String>) -> ActiveDialog {
    let mut selected_groups = Vec::new();
    if let Some(users_group) = available_groups
        .iter()
        .find(|g| g.eq_ignore_ascii_case("Users"))
    {
        selected_groups.push(users_group.clone());
    }
    ActiveDialog::AddUser {
        machine_idx,
        username: String::new(),
        full_name: String::new(),
        description: String::new(),
        password: String::new(),
        confirm_password: String::new(),
        must_change_pw: true,
        cannot_change_pw: false,
        pw_never_expires: false,
        account_disabled: false,
        show_advanced: false,
        profile: String::new(),
        script_path: String::new(),
        home_dir: String::new(),
        home_dir_drive: String::new(),
        available_groups,
        selected_groups,
        error: None,
    }
}

/// Builds an Edit User dialog initialized from level-4 properties.
pub fn make_edit_user_dialog(
    machine_idx: usize,
    user: UserAccount,
    member_groups: Vec<String>,
) -> ActiveDialog {
    let expires_enabled = user.acct_expires != TIMEQ_FOREVER && user.acct_expires != 0;
    let expires_date_text = if expires_enabled {
        user.formatted_expiration()
    } else {
        "2030-12-31".to_string()
    };
    ActiveDialog::EditUser {
        machine_idx,
        tab: EditUserTab::General,
        must_change_pw: user.password_expired,
        cannot_change_pw: user.cannot_change_password(),
        pw_never_expires: user.password_never_expires(),
        pw_not_required: user.password_not_required(),
        account_disabled: user.is_disabled(),
        account_locked: user.is_locked_out(),
        smartcard_required: user.smartcard_required(),
        expires_enabled,
        expires_date_text,
        user,
        member_groups,
        add_group_pick: String::new(),
        error: None,
    }
}

/// Builds a Set Password dialog.
pub fn make_set_password_dialog(machine_idx: usize, username: String) -> ActiveDialog {
    ActiveDialog::SetPassword {
        machine_idx,
        username,
        password: String::new(),
        confirm_password: String::new(),
        error: None,
    }
}

/// Builds an Add Group dialog.
pub fn make_add_group_dialog(machine_idx: usize) -> ActiveDialog {
    ActiveDialog::AddGroup {
        machine_idx,
        name: String::new(),
        description: String::new(),
        error: None,
    }
}

/// Builds an Edit Group dialog.
pub fn make_edit_group_dialog(
    machine_idx: usize,
    group: GroupAccount,
    members: Vec<GroupMember>,
) -> ActiveDialog {
    ActiveDialog::EditGroup {
        machine_idx,
        group,
        members,
        picker_filter: String::new(),
        manual_member: String::new(),
        error: None,
    }
}

/// Builds a Rename dialog for a user or local group.
pub fn make_rename_dialog(machine_idx: usize, is_user: bool, old_name: String) -> ActiveDialog {
    ActiveDialog::Rename {
        machine_idx,
        is_user,
        new_name: old_name.clone(),
        old_name,
        error: None,
    }
}

/// Builds a Connect Remote Computer dialog.
pub fn make_connect_dialog(recent_hosts: &[String]) -> ActiveDialog {
    ActiveDialog::ConnectRemote {
        host: String::new(),
        use_credentials: false,
        username: String::new(),
        password: String::new(),
        recent_hosts: recent_hosts.to_vec(),
        error: None,
    }
}

/// Builds a Global Search dialog.
pub fn make_global_search_dialog() -> ActiveDialog {
    ActiveDialog::GlobalSearch {
        query: String::new(),
        all_machines: false,
        include_users: true,
        include_groups: true,
        include_builtin: true,
    }
}

/// Search hit row computed inside the Global Search dialog.
#[derive(Clone)]
enum SearchHit {
    User {
        machine_idx: usize,
        machine_name: String,
        name: String,
        detail: String,
        is_disabled: bool,
    },
    Group {
        machine_idx: usize,
        machine_name: String,
        name: String,
        detail: String,
    },
    BuiltIn {
        machine_idx: usize,
        machine_name: String,
        principal: BuiltInPrincipal,
    },
}

impl AccountManagerApp {
    /// Renders whichever modal dialog is currently open.
    pub(crate) fn render_active_dialog(&mut self, ctx: &egui::Context, palette: Palette) {
        let Some(mut dialog) = self.dialog.take() else {
            return;
        };

        let mut keep_open = true;
        let mut follow_up: Option<ActiveDialog> = None;

        match &mut dialog {
            ActiveDialog::AddUser {
                machine_idx,
                username,
                full_name,
                description,
                password,
                confirm_password,
                must_change_pw,
                cannot_change_pw,
                pw_never_expires,
                account_disabled,
                show_advanced,
                profile,
                script_path,
                home_dir,
                home_dir_drive,
                available_groups,
                selected_groups,
                error,
            } => {
                let mut submitted = false;
                egui::Window::new("Add New Local User")
                    .collapsible(false)
                    .resizable(true)
                    .default_width(540.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        Grid::new("add_user_grid")
                            .num_columns(2)
                            .spacing([12.0_f32, 8.0_f32])
                            .show(ui, |ui| {
                                ui.label("User Name:");
                                ui.add(
                                    egui::TextEdit::singleline(username).desired_width(320.0_f32),
                                );
                                ui.end_row();

                                ui.label("Full Name:");
                                ui.add(
                                    egui::TextEdit::singleline(full_name).desired_width(320.0_f32),
                                );
                                ui.end_row();

                                ui.label("Description:");
                                ui.add(
                                    egui::TextEdit::singleline(description)
                                        .desired_width(320.0_f32),
                                );
                                ui.end_row();

                                ui.label("Password:");
                                ui.add(
                                    egui::TextEdit::singleline(password)
                                        .password(true)
                                        .desired_width(320.0_f32),
                                );
                                ui.end_row();

                                ui.label("Confirm Password:");
                                ui.add(
                                    egui::TextEdit::singleline(confirm_password)
                                        .password(true)
                                        .desired_width(320.0_f32),
                                );
                                ui.end_row();
                            });

                        ui.add_space(6.0_f32);
                        if ui
                            .checkbox(must_change_pw, "User must change password at next logon")
                            .changed()
                            && *must_change_pw
                        {
                            *cannot_change_pw = false;
                            *pw_never_expires = false;
                        }
                        if ui
                            .checkbox(cannot_change_pw, "User cannot change password")
                            .changed()
                            && *cannot_change_pw
                        {
                            *must_change_pw = false;
                        }
                        if ui
                            .checkbox(pw_never_expires, "Password never expires")
                            .changed()
                            && *pw_never_expires
                        {
                            *must_change_pw = false;
                        }
                        ui.checkbox(account_disabled, "Account is disabled");

                        ui.add_space(6.0_f32);
                        ui.checkbox(show_advanced, "Show profile paths and initial groups");
                        if *show_advanced {
                            ui.separator();
                            Grid::new("add_user_adv_grid")
                                .num_columns(2)
                                .spacing([12.0_f32, 6.0_f32])
                                .show(ui, |ui| {
                                    ui.label("Profile Path:");
                                    ui.add(
                                        egui::TextEdit::singleline(profile)
                                            .desired_width(320.0_f32),
                                    );
                                    ui.end_row();
                                    ui.label("Logon Script:");
                                    ui.add(
                                        egui::TextEdit::singleline(script_path)
                                            .desired_width(320.0_f32),
                                    );
                                    ui.end_row();
                                    ui.label("Home Folder:");
                                    ui.add(
                                        egui::TextEdit::singleline(home_dir)
                                            .desired_width(320.0_f32),
                                    );
                                    ui.end_row();
                                    ui.label("Home Drive (e.g. Z:):");
                                    ui.add(
                                        egui::TextEdit::singleline(home_dir_drive)
                                            .desired_width(100.0_f32),
                                    );
                                    ui.end_row();
                                });

                            ui.add_space(4.0_f32);
                            ui.label(RichText::new("Initial Local Groups:").strong());
                            ScrollArea::vertical().max_height(110.0_f32).show(ui, |ui| {
                                for group in available_groups.iter() {
                                    let mut checked = selected_groups.iter().any(|g| g == group);
                                    if ui.checkbox(&mut checked, group).changed() {
                                        if checked {
                                            selected_groups.push(group.clone());
                                        } else {
                                            selected_groups.retain(|g| g != group);
                                        }
                                    }
                                }
                            });
                        }

                        if let Some(err_msg) = error {
                            ui.add_space(6.0_f32);
                            ui.label(RichText::new(err_msg.as_str()).color(palette.danger));
                        }

                        ui.add_space(10.0_f32);
                        ui.horizontal(|ui| {
                            if ui.button("Create User").clicked() {
                                submitted = true;
                            }
                            if ui.button("Cancel").clicked() {
                                keep_open = false;
                            }
                        });
                    });

                if submitted {
                    if let Err(err) = validate_username(username) {
                        *error = Some(err.to_string());
                    } else if password != confirm_password {
                        *error = Some("Password and confirmation do not match.".to_string());
                    } else {
                        let mut flags = user_flags::UF_NORMAL_ACCOUNT | user_flags::UF_SCRIPT;
                        if *cannot_change_pw {
                            flags |= user_flags::UF_PASSWD_CANT_CHANGE;
                        }
                        if *pw_never_expires {
                            flags |= user_flags::UF_DONT_EXPIRE_PASSWD;
                        }
                        if *account_disabled {
                            flags |= user_flags::UF_ACCOUNTDISABLE;
                        }
                        let req = NewUserRequest {
                            name: username.trim().to_string(),
                            full_name: full_name.clone(),
                            comment: description.clone(),
                            password: password.clone(),
                            flags,
                            password_expired: *must_change_pw,
                            profile: profile.clone(),
                            script_path: script_path.clone(),
                            home_dir: home_dir.clone(),
                            home_dir_drive: home_dir_drive.clone(),
                            initial_groups: selected_groups.clone(),
                        };
                        let m_idx = *machine_idx;
                        let target = self.machines[m_idx].server_target.clone();
                        match self.backend.create_user(target.as_deref(), &req) {
                            Ok(()) => {
                                self.refresh_machine(m_idx);
                                if self.config.warn_no_groups && req.initial_groups.is_empty() {
                                    self.set_notice(
                                        NoticeKind::Warning,
                                        format!(
                                            "Created '{}'. Account belongs to no groups and cannot sign in interactively until added to a group.",
                                            req.name
                                        ),
                                    );
                                } else {
                                    self.set_notice(
                                        NoticeKind::Info,
                                        format!("Created user '{}'.", req.name),
                                    );
                                }
                                keep_open = false;
                            }
                            Err(err) => {
                                *error = Some(err.to_string());
                            }
                        }
                    }
                }
            }

            ActiveDialog::EditUser {
                machine_idx,
                tab,
                user,
                must_change_pw,
                cannot_change_pw,
                pw_never_expires,
                pw_not_required,
                account_disabled,
                account_locked,
                smartcard_required,
                expires_enabled,
                expires_date_text,
                member_groups,
                add_group_pick,
                error,
            } => {
                let m_idx = *machine_idx;
                let available_groups: Vec<String> = self.machines[m_idx]
                    .groups
                    .iter()
                    .map(|g| g.name.clone())
                    .collect();
                let mut save_clicked = false;
                let mut add_group_action: Option<String> = None;
                let mut remove_group_action: Option<String> = None;
                let tz_offset = self.tz_offset_hours;

                egui::Window::new(format!("User Properties - {}", user.name))
                    .collapsible(false)
                    .resizable(true)
                    .default_width(640.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            draw_user_icon_inline(ui, *account_disabled, palette);
                            ui.label(RichText::new(&user.name).heading().strong());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if !user.sid.is_empty() && ui.small_button("Copy SID").clicked() {
                                    ui.ctx().copy_text(user.sid.clone());
                                }
                                ui.label(RichText::new(&user.sid).small().color(palette.text_muted));
                            });
                        });
                        ui.separator();

                        ui.horizontal(|ui| {
                            ui.selectable_value(tab, EditUserTab::General, "General");
                            ui.selectable_value(tab, EditUserTab::MemberOf, "Member Of");
                            ui.selectable_value(tab, EditUserTab::Profile, "Profile");
                            ui.selectable_value(tab, EditUserTab::LogonHours, "Logon Hours");
                        });
                        ui.separator();

                        match *tab {
                            EditUserTab::General => {
                                Grid::new("edit_user_general")
                                    .num_columns(2)
                                    .spacing([12.0_f32, 6.0_f32])
                                    .show(ui, |ui| {
                                        ui.label("Full Name:");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut user.full_name)
                                                .desired_width(360.0_f32),
                                        );
                                        ui.end_row();
                                        ui.label("Description:");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut user.comment)
                                                .desired_width(360.0_f32),
                                        );
                                        ui.end_row();
                                    });

                                ui.add_space(6.0_f32);
                                if ui
                                    .checkbox(
                                        must_change_pw,
                                        "User must change password at next logon",
                                    )
                                    .changed()
                                    && *must_change_pw
                                {
                                    *cannot_change_pw = false;
                                    *pw_never_expires = false;
                                }
                                if ui
                                    .checkbox(cannot_change_pw, "User cannot change password")
                                    .changed()
                                    && *cannot_change_pw
                                {
                                    *must_change_pw = false;
                                }
                                if ui
                                    .checkbox(pw_never_expires, "Password never expires")
                                    .changed()
                                    && *pw_never_expires
                                {
                                    *must_change_pw = false;
                                }
                                ui.checkbox(pw_not_required, "Password not required");
                                ui.checkbox(account_disabled, "Account is disabled");
                                ui.add_enabled(
                                    *account_locked,
                                    egui::Checkbox::new(
                                        account_locked,
                                        "Account is locked out (clear to unlock)",
                                    ),
                                );
                                ui.checkbox(
                                    smartcard_required,
                                    "Smart card is required for interactive logon",
                                );

                                ui.add_space(6.0_f32);
                                ui.horizontal(|ui| {
                                    ui.checkbox(expires_enabled, "Account expires on (YYYY-MM-DD):");
                                    ui.add_enabled(
                                        *expires_enabled,
                                        egui::TextEdit::singleline(expires_date_text)
                                            .desired_width(130.0_f32),
                                    );
                                });

                                ui.separator();
                                Grid::new("edit_user_meta")
                                    .num_columns(2)
                                    .spacing([12.0_f32, 4.0_f32])
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new("Last Logon:")
                                                .color(palette.text_muted),
                                        );
                                        ui.label(user.formatted_last_logon());
                                        ui.end_row();

                                        ui.label(
                                            RichText::new("Password Last Changed:")
                                                .color(palette.text_muted),
                                        );
                                        ui.label(user.formatted_password_last_set());
                                        ui.end_row();

                                        ui.label(
                                            RichText::new("Failed Password Attempts:")
                                                .color(palette.text_muted),
                                        );
                                        ui.label(user.bad_pw_count.to_string());
                                        ui.end_row();
                                    });
                            }
                            EditUserTab::MemberOf => {
                                if member_groups.is_empty() && self.config.warn_no_groups {
                                    ui.label(
                                        RichText::new(
                                            "Warning: This account belongs to no local groups and may not be able to sign in.",
                                        )
                                        .color(palette.warning),
                                    );
                                    ui.add_space(4.0_f32);
                                }
                                ScrollArea::vertical()
                                    .max_height(190.0_f32)
                                    .show(ui, |ui| {
                                        for grp in member_groups.iter() {
                                            ui.horizontal(|ui| {
                                                draw_group_icon_inline(ui, palette);
                                                ui.label(grp);
                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        if ui.small_button("Remove").clicked() {
                                                            remove_group_action = Some(grp.clone());
                                                        }
                                                    },
                                                );
                                            });
                                        }
                                    });
                                ui.separator();
                                ui.horizontal(|ui| {
                                    ui.label("Add to Group:");
                                    egui::ComboBox::from_id_salt("add_user_group_combo")
                                        .selected_text(if add_group_pick.is_empty() {
                                            "Select a group..."
                                        } else {
                                            add_group_pick.as_str()
                                        })
                                        .width(240.0_f32)
                                        .show_ui(ui, |ui| {
                                            for grp in &available_groups {
                                                if !member_groups
                                                    .iter()
                                                    .any(|m| m.eq_ignore_ascii_case(grp))
                                                {
                                                    ui.selectable_value(
                                                        add_group_pick,
                                                        grp.clone(),
                                                        grp,
                                                    );
                                                }
                                            }
                                        });
                                    if ui
                                        .add_enabled(
                                            !add_group_pick.is_empty(),
                                            egui::Button::new("Add"),
                                        )
                                        .clicked()
                                    {
                                        add_group_action = Some(add_group_pick.clone());
                                    }
                                });
                            }
                            EditUserTab::Profile => {
                                Grid::new("edit_user_profile")
                                    .num_columns(2)
                                    .spacing([12.0_f32, 8.0_f32])
                                    .show(ui, |ui| {
                                        ui.label("Profile Path:");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut user.profile)
                                                .desired_width(360.0_f32),
                                        );
                                        ui.end_row();
                                        ui.label("Logon Script:");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut user.script_path)
                                                .desired_width(360.0_f32),
                                        );
                                        ui.end_row();
                                        ui.label("Home Folder Path:");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut user.home_dir)
                                                .desired_width(360.0_f32),
                                        );
                                        ui.end_row();
                                        ui.label("Connect Drive Letter:");
                                        ui.add(
                                            egui::TextEdit::singleline(&mut user.home_dir_drive)
                                                .desired_width(100.0_f32),
                                        );
                                        ui.end_row();
                                    });
                            }
                            EditUserTab::LogonHours => {
                                render_logon_hours_editor(
                                    ui,
                                    &mut user.logon_hours,
                                    tz_offset,
                                    palette,
                                );
                            }
                        }

                        if let Some(err_msg) = error {
                            ui.add_space(6.0_f32);
                            ui.label(RichText::new(err_msg.as_str()).color(palette.danger));
                        }

                        ui.add_space(10.0_f32);
                        ui.horizontal(|ui| {
                            if ui.button("Save Changes").clicked() {
                                save_clicked = true;
                            }
                            if ui.button("Close").clicked() {
                                keep_open = false;
                            }
                        });
                    });

                if let Some(grp) = add_group_action {
                    let target = self.machines[m_idx].server_target.clone();
                    match self.backend.add_group_member(
                        target.as_deref(),
                        &grp,
                        &user.name,
                        Some(&user.sid),
                    ) {
                        Ok(()) => {
                            member_groups.push(grp);
                            member_groups.sort_by_key(|a| a.to_lowercase());
                            add_group_pick.clear();
                            *error = None;
                        }
                        Err(err) => *error = Some(err.to_string()),
                    }
                }
                if let Some(grp) = remove_group_action {
                    let target = self.machines[m_idx].server_target.clone();
                    match self.backend.remove_group_member(
                        target.as_deref(),
                        &grp,
                        &user.name,
                        Some(&user.sid),
                    ) {
                        Ok(()) => {
                            member_groups.retain(|g| !g.eq_ignore_ascii_case(&grp));
                            *error = None;
                        }
                        Err(err) => *error = Some(err.to_string()),
                    }
                }

                if save_clicked {
                    let acct_expires = if *expires_enabled {
                        match parse_expiration_date(expires_date_text) {
                            Ok(ts) => ts,
                            Err(err) => {
                                *error = Some(err.to_string());
                                self.dialog = Some(dialog);
                                return;
                            }
                        }
                    } else {
                        TIMEQ_FOREVER
                    };

                    let mut new_flags = user.flags;
                    set_flag(
                        &mut new_flags,
                        user_flags::UF_ACCOUNTDISABLE,
                        *account_disabled,
                    );
                    set_flag(&mut new_flags, user_flags::UF_LOCKOUT, *account_locked);
                    set_flag(
                        &mut new_flags,
                        user_flags::UF_PASSWD_CANT_CHANGE,
                        *cannot_change_pw,
                    );
                    set_flag(
                        &mut new_flags,
                        user_flags::UF_DONT_EXPIRE_PASSWD,
                        *pw_never_expires,
                    );
                    set_flag(
                        &mut new_flags,
                        user_flags::UF_PASSWD_NOTREQD,
                        *pw_not_required,
                    );
                    set_flag(
                        &mut new_flags,
                        user_flags::UF_SMARTCARD_REQUIRED,
                        *smartcard_required,
                    );

                    let req = UserUpdateRequest {
                        name: user.name.clone(),
                        full_name: user.full_name.clone(),
                        comment: user.comment.clone(),
                        flags: new_flags,
                        password_expired: *must_change_pw,
                        acct_expires,
                        profile: user.profile.clone(),
                        script_path: user.script_path.clone(),
                        home_dir: user.home_dir.clone(),
                        home_dir_drive: user.home_dir_drive.clone(),
                        logon_hours: user.logon_hours.clone(),
                    };
                    let target = self.machines[m_idx].server_target.clone();
                    match self.backend.update_user(target.as_deref(), &req) {
                        Ok(()) => {
                            self.refresh_machine(m_idx);
                            self.set_notice(
                                NoticeKind::Info,
                                format!("Updated user '{}'.", req.name),
                            );
                            keep_open = false;
                        }
                        Err(err) => *error = Some(err.to_string()),
                    }
                }
            }

            ActiveDialog::SetPassword {
                machine_idx,
                username,
                password,
                confirm_password,
                error,
            } => {
                let mut submit = false;
                egui::Window::new(format!("Set Password - {username}"))
                    .collapsible(false)
                    .resizable(false)
                    .default_width(440.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.label(
                            RichText::new(
                                "Resetting a password may revoke access to EFS-encrypted files and stored credentials for this account.",
                            )
                            .color(palette.warning),
                        );
                        ui.add_space(6.0_f32);
                        Grid::new("set_pw_grid")
                            .num_columns(2)
                            .spacing([12.0_f32, 8.0_f32])
                            .show(ui, |ui| {
                                ui.label("New Password:");
                                ui.add(
                                    egui::TextEdit::singleline(password)
                                        .password(true)
                                        .desired_width(240.0_f32),
                                );
                                ui.end_row();
                                ui.label("Confirm Password:");
                                ui.add(
                                    egui::TextEdit::singleline(confirm_password)
                                        .password(true)
                                        .desired_width(240.0_f32),
                                );
                                ui.end_row();
                            });

                        if let Some(err_msg) = error {
                            ui.add_space(6.0_f32);
                            ui.label(RichText::new(err_msg.as_str()).color(palette.danger));
                        }

                        ui.add_space(8.0_f32);
                        ui.horizontal(|ui| {
                            if ui.button("Set Password").clicked() {
                                submit = true;
                            }
                            if ui.button("Cancel").clicked() {
                                keep_open = false;
                            }
                        });
                    });

                if submit {
                    if password != confirm_password {
                        *error = Some("Passwords do not match.".to_string());
                    } else {
                        let m_idx = *machine_idx;
                        let target = self.machines[m_idx].server_target.clone();
                        match self
                            .backend
                            .set_user_password(target.as_deref(), username, password)
                        {
                            Ok(()) => {
                                self.refresh_machine(m_idx);
                                self.set_notice(
                                    NoticeKind::Info,
                                    format!("Password updated for '{username}'."),
                                );
                                keep_open = false;
                            }
                            Err(err) => *error = Some(err.to_string()),
                        }
                    }
                }
            }

            ActiveDialog::AddGroup {
                machine_idx,
                name,
                description,
                error,
            } => {
                let mut submit = false;
                egui::Window::new("Add New Local Group")
                    .collapsible(false)
                    .resizable(false)
                    .default_width(460.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        Grid::new("add_group_grid")
                            .num_columns(2)
                            .spacing([12.0_f32, 8.0_f32])
                            .show(ui, |ui| {
                                ui.label("Group Name:");
                                ui.add(egui::TextEdit::singleline(name).desired_width(280.0_f32));
                                ui.end_row();
                                ui.label("Description:");
                                ui.add(
                                    egui::TextEdit::singleline(description)
                                        .desired_width(280.0_f32),
                                );
                                ui.end_row();
                            });

                        if let Some(err_msg) = error {
                            ui.add_space(6.0_f32);
                            ui.label(RichText::new(err_msg.as_str()).color(palette.danger));
                        }

                        ui.add_space(8.0_f32);
                        ui.horizontal(|ui| {
                            if ui.button("Create Group").clicked() {
                                submit = true;
                            }
                            if ui.button("Cancel").clicked() {
                                keep_open = false;
                            }
                        });
                    });

                if submit {
                    if let Err(err) = validate_group_name(name) {
                        *error = Some(err.to_string());
                    } else {
                        let m_idx = *machine_idx;
                        let target = self.machines[m_idx].server_target.clone();
                        match self
                            .backend
                            .create_group(target.as_deref(), name.trim(), description)
                        {
                            Ok(()) => {
                                self.refresh_machine(m_idx);
                                self.set_notice(
                                    NoticeKind::Info,
                                    format!("Created group '{}'.", name.trim()),
                                );
                                keep_open = false;
                            }
                            Err(err) => *error = Some(err.to_string()),
                        }
                    }
                }
            }

            ActiveDialog::EditGroup {
                machine_idx,
                group,
                members,
                picker_filter,
                manual_member,
                error,
            } => {
                let m_idx = *machine_idx;
                let known_users = self.machines[m_idx].users.clone();
                let known_builtins = self.machines[m_idx].builtins.clone();
                let mut save_comment = false;
                let mut add_member_req: Option<(String, Option<String>)> = None;
                let mut remove_member_req: Option<(String, Option<String>)> = None;

                egui::Window::new(format!("Group Properties - {}", group.name))
                    .collapsible(false)
                    .resizable(true)
                    .default_width(620.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            draw_group_icon_inline(ui, palette);
                            ui.label(RichText::new(&group.name).heading().strong());
                        });
                        ui.add_space(4.0_f32);
                        ui.horizontal(|ui| {
                            ui.label("Description:");
                            ui.add(
                                egui::TextEdit::singleline(&mut group.comment)
                                    .desired_width(380.0_f32),
                            );
                            if ui.button("Save Description").clicked() {
                                save_comment = true;
                            }
                        });
                        ui.separator();

                        ui.label(
                            RichText::new(format!("Current Members ({}):", members.len())).strong(),
                        );
                        Frame::NONE
                            .stroke(Stroke::new(1.0_f32, palette.border))
                            .corner_radius(CornerRadius::same(4))
                            .inner_margin(Margin::same(6))
                            .show(ui, |ui| {
                                ScrollArea::vertical()
                                    .id_salt("group_members_scroll")
                                    .max_height(170.0_f32)
                                    .show(ui, |ui| {
                                        if members.is_empty() {
                                            ui.label(
                                                RichText::new("This group has no members.")
                                                    .color(palette.text_muted),
                                            );
                                        }
                                        for member in members.iter() {
                                            ui.horizontal(|ui| {
                                                draw_member_icon_inline(ui, member, palette);
                                                ui.label(&member.domain_and_name);
                                                if member.is_disabled == Some(true) {
                                                    ui.label(
                                                        RichText::new("(Disabled)")
                                                            .small()
                                                            .color(palette.danger),
                                                    );
                                                }
                                                ui.label(
                                                    RichText::new(member.kind.label())
                                                        .small()
                                                        .color(palette.text_muted),
                                                );
                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        if ui.small_button("Remove").clicked() {
                                                            remove_member_req = Some((
                                                                member.domain_and_name.clone(),
                                                                Some(member.sid.clone()),
                                                            ));
                                                        }
                                                    },
                                                );
                                            });
                                        }
                                    });
                            });

                        ui.add_space(6.0_f32);
                        ui.label(
                            RichText::new("Add Member from Local Accounts or Built-in Principals:")
                                .strong(),
                        );
                        ui.horizontal(|ui| {
                            ui.label("Filter:");
                            ui.add(
                                egui::TextEdit::singleline(picker_filter)
                                    .desired_width(240.0_f32)
                                    .hint_text("Type account name..."),
                            );
                        });
                        let q = picker_filter.trim().to_lowercase();
                        Frame::NONE
                            .stroke(Stroke::new(1.0_f32, palette.border))
                            .corner_radius(CornerRadius::same(4))
                            .inner_margin(Margin::same(6))
                            .show(ui, |ui| {
                                ScrollArea::vertical()
                                    .id_salt("group_add_picker_scroll")
                                    .max_height(130.0_f32)
                                    .show(ui, |ui| {
                                        for u in &known_users {
                                            if !q.is_empty() && !u.name.to_lowercase().contains(&q)
                                            {
                                                continue;
                                            }
                                            let already = members
                                                .iter()
                                                .any(|m| m.name.eq_ignore_ascii_case(&u.name));
                                            if already {
                                                continue;
                                            }
                                            ui.horizontal(|ui| {
                                                draw_user_icon_inline(ui, u.is_disabled(), palette);
                                                ui.label(&u.name);
                                                if u.is_disabled() {
                                                    ui.label(
                                                        RichText::new("(Disabled)")
                                                            .small()
                                                            .color(palette.danger),
                                                    );
                                                }
                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        if ui.small_button("Add").clicked() {
                                                            add_member_req = Some((
                                                                u.name.clone(),
                                                                Some(u.sid.clone()),
                                                            ));
                                                        }
                                                    },
                                                );
                                            });
                                        }
                                        for b in &known_builtins {
                                            if !q.is_empty()
                                                && !b.name.to_lowercase().contains(&q)
                                                && !b.sid.to_lowercase().contains(&q)
                                            {
                                                continue;
                                            }
                                            let already = members.iter().any(|m| m.sid == b.sid);
                                            if already {
                                                continue;
                                            }
                                            ui.horizontal(|ui| {
                                                draw_builtin_icon_inline(ui, palette);
                                                ui.label(format!("{} ({})", b.name, b.sid));
                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        if ui.small_button("Add").clicked() {
                                                            add_member_req = Some((
                                                                b.name.clone(),
                                                                Some(b.sid.clone()),
                                                            ));
                                                        }
                                                    },
                                                );
                                            });
                                        }
                                    });
                            });

                        ui.add_space(4.0_f32);
                        ui.horizontal(|ui| {
                            ui.label("Manual DOMAIN\\Account:");
                            ui.add(
                                egui::TextEdit::singleline(manual_member).desired_width(220.0_f32),
                            );
                            if ui
                                .add_enabled(
                                    !manual_member.trim().is_empty(),
                                    egui::Button::new("Add Name"),
                                )
                                .clicked()
                            {
                                add_member_req = Some((manual_member.trim().to_string(), None));
                            }
                        });

                        if let Some(err_msg) = error {
                            ui.add_space(6.0_f32);
                            ui.label(RichText::new(err_msg.as_str()).color(palette.danger));
                        }

                        ui.add_space(8.0_f32);
                        if ui.button("Close").clicked() {
                            keep_open = false;
                        }
                    });

                let target = self.machines[m_idx].server_target.clone();
                if save_comment {
                    match self.backend.update_group_comment(
                        target.as_deref(),
                        &group.name,
                        &group.comment,
                    ) {
                        Ok(()) => {
                            self.refresh_machine(m_idx);
                            self.set_notice(
                                NoticeKind::Info,
                                format!("Updated description for '{}'.", group.name),
                            );
                            *error = None;
                        }
                        Err(err) => *error = Some(err.to_string()),
                    }
                }
                if let Some((member_name, member_sid)) = add_member_req {
                    match self.backend.add_group_member(
                        target.as_deref(),
                        &group.name,
                        &member_name,
                        member_sid.as_deref(),
                    ) {
                        Ok(()) => {
                            manual_member.clear();
                            if let Ok(updated) = self.backend.list_group_members(
                                target.as_deref(),
                                &group.name,
                                &self.machines[m_idx].users,
                            ) {
                                *members = updated;
                            }
                            *error = None;
                        }
                        Err(err) => *error = Some(err.to_string()),
                    }
                }
                if let Some((member_name, member_sid)) = remove_member_req {
                    match self.backend.remove_group_member(
                        target.as_deref(),
                        &group.name,
                        &member_name,
                        member_sid.as_deref(),
                    ) {
                        Ok(()) => {
                            if let Ok(updated) = self.backend.list_group_members(
                                target.as_deref(),
                                &group.name,
                                &self.machines[m_idx].users,
                            ) {
                                *members = updated;
                            }
                            *error = None;
                        }
                        Err(err) => *error = Some(err.to_string()),
                    }
                }
            }

            ActiveDialog::Rename {
                machine_idx,
                is_user,
                old_name,
                new_name,
                error,
            } => {
                let mut submit = false;
                let title = if *is_user {
                    format!("Rename User - {old_name}")
                } else {
                    format!("Rename Group - {old_name}")
                };
                egui::Window::new(title)
                    .collapsible(false)
                    .resizable(false)
                    .default_width(420.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("New Name:");
                            ui.add(egui::TextEdit::singleline(new_name).desired_width(260.0_f32));
                        });
                        if let Some(err_msg) = error {
                            ui.add_space(6.0_f32);
                            ui.label(RichText::new(err_msg.as_str()).color(palette.danger));
                        }
                        ui.add_space(8.0_f32);
                        ui.horizontal(|ui| {
                            if ui.button("Rename").clicked() {
                                submit = true;
                            }
                            if ui.button("Cancel").clicked() {
                                keep_open = false;
                            }
                        });
                    });

                if submit {
                    let m_idx = *machine_idx;
                    let target = self.machines[m_idx].server_target.clone();
                    let res = if *is_user {
                        self.backend
                            .rename_user(target.as_deref(), old_name, new_name.trim())
                    } else {
                        self.backend
                            .rename_group(target.as_deref(), old_name, new_name.trim())
                    };
                    match res {
                        Ok(()) => {
                            self.selected_items.clear();
                            self.refresh_machine(m_idx);
                            self.set_notice(
                                NoticeKind::Info,
                                format!("Renamed '{old_name}' to '{}'.", new_name.trim()),
                            );
                            keep_open = false;
                        }
                        Err(err) => *error = Some(err.to_string()),
                    }
                }
            }

            ActiveDialog::ConfirmDelete {
                machine_idx,
                is_user,
                names,
            } => {
                let mut confirm = false;
                let noun = if *is_user { "user" } else { "group" };
                egui::Window::new("Confirm Deletion")
                    .collapsible(false)
                    .resizable(false)
                    .default_width(440.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.label(format!(
                            "Delete {} selected {noun}(s) permanently? Security identifiers (SIDs) cannot be restored after deletion.",
                            names.len()
                        ));
                        ui.add_space(6.0_f32);
                        for item in names.iter().take(10) {
                            ui.label(format!("- {item}"));
                        }
                        if names.len() > 10 {
                            ui.label(format!("... and {} more", names.len() - 10));
                        }
                        ui.add_space(10.0_f32);
                        ui.horizontal(|ui| {
                            if ui
                                .button(RichText::new("Delete Permanently").color(palette.danger))
                                .clicked()
                            {
                                confirm = true;
                            }
                            if ui.button("Cancel").clicked() {
                                keep_open = false;
                            }
                        });
                    });

                if confirm {
                    let m_idx = *machine_idx;
                    let user_flag = *is_user;
                    let list = names.clone();
                    self.execute_delete(m_idx, user_flag, &list);
                    keep_open = false;
                }
            }

            ActiveDialog::ConfirmDisconnect { machine_idx, host } => {
                let mut confirm = false;
                egui::Window::new("Disconnect Remote Computer")
                    .collapsible(false)
                    .resizable(false)
                    .default_width(400.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.label(format!("Disconnect from remote computer '{host}'?"));
                        ui.add_space(10.0_f32);
                        ui.horizontal(|ui| {
                            if ui.button("Disconnect").clicked() {
                                confirm = true;
                            }
                            if ui.button("Cancel").clicked() {
                                keep_open = false;
                            }
                        });
                    });
                if confirm {
                    let idx = *machine_idx;
                    self.disconnect_machine(idx);
                    keep_open = false;
                }
            }

            ActiveDialog::ConnectRemote {
                host,
                use_credentials,
                username,
                password,
                recent_hosts,
                error,
            } => {
                let mut connect = false;
                egui::Window::new("Connect to Remote Computer")
                    .collapsible(false)
                    .resizable(false)
                    .default_width(480.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        Grid::new("connect_remote_grid")
                            .num_columns(2)
                            .spacing([12.0_f32, 8.0_f32])
                            .show(ui, |ui| {
                                ui.label("Computer Name or IP:");
                                ui.add(
                                    egui::TextEdit::singleline(host)
                                        .desired_width(280.0_f32)
                                        .hint_text("SERVER01 or 192.168.1.50"),
                                );
                                ui.end_row();
                            });

                        if !recent_hosts.is_empty() {
                            ui.add_space(4.0_f32);
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new("Recent:").color(palette.text_muted));
                                for item in recent_hosts.iter() {
                                    if ui.small_button(item).clicked() {
                                        *host = item.clone();
                                    }
                                }
                            });
                        }

                        ui.add_space(6.0_f32);
                        ui.checkbox(
                            use_credentials,
                            "Authenticate with explicit IPC$ credentials",
                        );
                        if *use_credentials {
                            Grid::new("connect_creds_grid")
                                .num_columns(2)
                                .spacing([12.0_f32, 6.0_f32])
                                .show(ui, |ui| {
                                    ui.label("Username (DOMAIN\\User):");
                                    ui.add(
                                        egui::TextEdit::singleline(username)
                                            .desired_width(260.0_f32),
                                    );
                                    ui.end_row();
                                    ui.label("Password:");
                                    ui.add(
                                        egui::TextEdit::singleline(password)
                                            .password(true)
                                            .desired_width(260.0_f32),
                                    );
                                    ui.end_row();
                                });
                        }

                        if let Some(err_msg) = error {
                            ui.add_space(6.0_f32);
                            ui.label(RichText::new(err_msg.as_str()).color(palette.danger));
                        }

                        ui.add_space(10.0_f32);
                        ui.horizontal(|ui| {
                            if ui.button("Connect").clicked() {
                                connect = true;
                            }
                            if ui.button("Cancel").clicked() {
                                keep_open = false;
                            }
                        });
                    });

                if connect {
                    let u_opt = if *use_credentials {
                        Some(username.as_str())
                    } else {
                        None
                    };
                    let p_opt = if *use_credentials {
                        Some(password.as_str())
                    } else {
                        None
                    };
                    match self.connect_remote_machine(host, u_opt, p_opt) {
                        Ok(()) => keep_open = false,
                        Err(err) => *error = Some(err),
                    }
                }
            }

            ActiveDialog::GlobalSearch {
                query,
                all_machines,
                include_users,
                include_groups,
                include_builtin,
            } => {
                let q = query.trim().to_lowercase();
                let mut hits: Vec<SearchHit> = Vec::new();
                for (m_idx, machine) in self.machines.iter().enumerate() {
                    if !*all_machines && m_idx != self.selected_machine {
                        continue;
                    }
                    if *include_users {
                        for u in &machine.users {
                            if q.is_empty()
                                || u.name.to_lowercase().contains(&q)
                                || u.full_name.to_lowercase().contains(&q)
                                || u.comment.to_lowercase().contains(&q)
                                || u.sid.to_lowercase().contains(&q)
                            {
                                hits.push(SearchHit::User {
                                    machine_idx: m_idx,
                                    machine_name: machine.display_name.clone(),
                                    name: u.name.clone(),
                                    detail: format!("{} - {}", u.status_label(), u.comment),
                                    is_disabled: u.is_disabled(),
                                });
                            }
                        }
                    }
                    if *include_groups {
                        for g in &machine.groups {
                            if q.is_empty()
                                || g.name.to_lowercase().contains(&q)
                                || g.comment.to_lowercase().contains(&q)
                            {
                                hits.push(SearchHit::Group {
                                    machine_idx: m_idx,
                                    machine_name: machine.display_name.clone(),
                                    name: g.name.clone(),
                                    detail: g.comment.clone(),
                                });
                            }
                        }
                    }
                    if *include_builtin {
                        for b in &machine.builtins {
                            if q.is_empty()
                                || b.name.to_lowercase().contains(&q)
                                || b.sid.to_lowercase().contains(&q)
                                || b.domain.to_lowercase().contains(&q)
                            {
                                hits.push(SearchHit::BuiltIn {
                                    machine_idx: m_idx,
                                    machine_name: machine.display_name.clone(),
                                    principal: b.clone(),
                                });
                            }
                        }
                    }
                }

                let mut jump_target: Option<(usize, ViewKind, String)> = None;
                let mut open_edit: Option<(usize, bool, String)> = None;

                egui::Window::new("Global Account Search")
                    .collapsible(false)
                    .resizable(true)
                    .default_width(680.0_f32)
                    .default_height(460.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Search:");
                            ui.add(
                                egui::TextEdit::singleline(query)
                                    .desired_width(320.0_f32)
                                    .hint_text("Name, full name, description, or SID..."),
                            );
                            ui.checkbox(all_machines, "All connected computers");
                        });
                        ui.horizontal(|ui| {
                            ui.checkbox(include_users, "Users");
                            ui.checkbox(include_groups, "Groups");
                            ui.checkbox(include_builtin, "Built-in Principals");
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(
                                    RichText::new(format!("{} matches", hits.len()))
                                        .color(palette.text_muted),
                                );
                            });
                        });
                        ui.separator();

                        ScrollArea::vertical().max_height(310.0_f32).show(ui, |ui| {
                            for hit in &hits {
                                match hit {
                                    SearchHit::User {
                                        machine_idx,
                                        machine_name,
                                        name,
                                        detail,
                                        is_disabled,
                                    } => {
                                        ui.horizontal(|ui| {
                                            draw_user_icon_inline(ui, *is_disabled, palette);
                                            ui.label(RichText::new(name).strong());
                                            ui.label(
                                                RichText::new(format!("[{machine_name}]"))
                                                    .small()
                                                    .color(palette.text_muted),
                                            );
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(detail).color(palette.text_muted),
                                                )
                                                .truncate(),
                                            );
                                            ui.with_layout(
                                                Layout::right_to_left(Align::Center),
                                                |ui| {
                                                    if ui.small_button("Edit").clicked() {
                                                        open_edit = Some((
                                                            *machine_idx,
                                                            true,
                                                            name.clone(),
                                                        ));
                                                    }
                                                    if ui.small_button("Go To").clicked() {
                                                        jump_target = Some((
                                                            *machine_idx,
                                                            ViewKind::Users,
                                                            name.clone(),
                                                        ));
                                                    }
                                                },
                                            );
                                        });
                                    }
                                    SearchHit::Group {
                                        machine_idx,
                                        machine_name,
                                        name,
                                        detail,
                                    } => {
                                        ui.horizontal(|ui| {
                                            draw_group_icon_inline(ui, palette);
                                            ui.label(RichText::new(name).strong());
                                            ui.label(
                                                RichText::new(format!("[{machine_name}]"))
                                                    .small()
                                                    .color(palette.text_muted),
                                            );
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(detail).color(palette.text_muted),
                                                )
                                                .truncate(),
                                            );
                                            ui.with_layout(
                                                Layout::right_to_left(Align::Center),
                                                |ui| {
                                                    if ui.small_button("Edit").clicked() {
                                                        open_edit = Some((
                                                            *machine_idx,
                                                            false,
                                                            name.clone(),
                                                        ));
                                                    }
                                                    if ui.small_button("Go To").clicked() {
                                                        jump_target = Some((
                                                            *machine_idx,
                                                            ViewKind::Groups,
                                                            name.clone(),
                                                        ));
                                                    }
                                                },
                                            );
                                        });
                                    }
                                    SearchHit::BuiltIn {
                                        machine_idx,
                                        machine_name,
                                        principal,
                                    } => {
                                        ui.horizontal(|ui| {
                                            draw_builtin_icon_inline(ui, palette);
                                            ui.label(RichText::new(&principal.name).strong());
                                            ui.label(
                                                RichText::new(format!(
                                                    "[{machine_name}] {}",
                                                    principal.sid
                                                ))
                                                .small()
                                                .color(palette.text_muted),
                                            );
                                            ui.with_layout(
                                                Layout::right_to_left(Align::Center),
                                                |ui| {
                                                    if ui.small_button("Go To").clicked() {
                                                        jump_target = Some((
                                                            *machine_idx,
                                                            ViewKind::BuiltIn,
                                                            principal.sid.clone(),
                                                        ));
                                                    }
                                                },
                                            );
                                        });
                                    }
                                }
                            }
                        });

                        ui.add_space(6.0_f32);
                        if ui.button("Close").clicked() {
                            keep_open = false;
                        }
                    });

                if let Some((m_idx, view, key)) = jump_target {
                    self.selected_machine = m_idx;
                    self.active_view = view;
                    self.quick_search.clear();
                    self.selected_items.clear();
                    self.selected_items.insert(key);
                    keep_open = false;
                } else if let Some((m_idx, is_user, name)) = open_edit {
                    keep_open = false;
                    if is_user {
                        self.open_edit_user(m_idx, &name);
                        follow_up = self.dialog.take();
                    } else {
                        self.open_edit_group(m_idx, &name);
                        follow_up = self.dialog.take();
                    }
                }
            }

            ActiveDialog::BuiltInDetails(principal) => {
                egui::Window::new("Built-in Security Principal")
                    .collapsible(false)
                    .resizable(false)
                    .default_width(480.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        Grid::new("builtin_details_grid")
                            .num_columns(2)
                            .spacing([12.0_f32, 8.0_f32])
                            .show(ui, |ui| {
                                ui.label("Name:");
                                ui.label(RichText::new(&principal.name).strong());
                                ui.end_row();
                                ui.label("Authority / Domain:");
                                ui.label(if principal.domain.is_empty() {
                                    "None"
                                } else {
                                    principal.domain.as_str()
                                });
                                ui.end_row();
                                ui.label("Security Identifier (SID):");
                                ui.label(&principal.sid);
                                ui.end_row();
                            });

                        ui.add_space(10.0_f32);
                        ui.horizontal(|ui| {
                            if ui.button("Copy Name").clicked() {
                                ui.ctx().copy_text(principal.name.clone());
                            }
                            if ui.button("Copy SID").clicked() {
                                ui.ctx().copy_text(principal.sid.clone());
                            }
                            if ui.button("Close").clicked() {
                                keep_open = false;
                            }
                        });
                    });
            }

            ActiveDialog::Settings => {
                let mut changed = false;
                egui::Window::new("Settings and Warnings")
                    .collapsible(false)
                    .resizable(false)
                    .default_width(460.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        changed |= ui
                            .checkbox(
                                &mut self.config.warn_delete,
                                "Confirm before deleting users or local groups",
                            )
                            .changed();
                        changed |= ui
                            .checkbox(
                                &mut self.config.warn_no_groups,
                                "Warn when a user account belongs to no local groups",
                            )
                            .changed();
                        changed |= ui
                            .checkbox(
                                &mut self.config.warn_disconnect,
                                "Confirm before disconnecting from a remote computer",
                            )
                            .changed();
                        changed |= ui
                            .checkbox(
                                &mut self.config.show_sid_in_users,
                                "Show Security Identifier (SID) column in Users table",
                            )
                            .changed();

                        ui.add_space(10.0_f32);
                        if ui.button("Close").clicked() {
                            keep_open = false;
                        }
                    });
                if changed {
                    let _ = self.config.save();
                }
            }

            ActiveDialog::About => {
                egui::Window::new("About Local User and Group Management")
                    .collapsible(false)
                    .resizable(false)
                    .default_width(500.0_f32)
                    .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                    .show(ctx, |ui| {
                        ui.label(
                            RichText::new(format!(
                                "Local User and Group Management (lusrmgr) v{APP_VERSION}"
                            ))
                            .heading()
                            .strong(),
                        );
                        ui.add_space(6.0_f32);
                        ui.label("Native Rust alternative to the Windows lusrmgr.msc snap-in for all Windows editions, built on Win32 NetAPI32, LSA, WNet, and eframe/egui.");
                        ui.add_space(6.0_f32);
                        ui.label("License: GNU General Public License v3.0 (GPL-3.0-only)");
                        ui.label("Rust Port Maintainer: Aaron Christopher Ramos");
                        ui.label("Original VB.NET Project Author: akruhler (AccountManagement / lusrmgr)");
                        ui.add_space(6.0_f32);
                        ui.hyperlink_to(
                            "Fork Repository (aaron-c-s-ramos/AccountManagement)",
                            "https://github.com/aaron-c-s-ramos/AccountManagement",
                        );
                        ui.hyperlink_to(
                            "Upstream Repository (akruhler/AccountManagement)",
                            "https://github.com/akruhler/AccountManagement",
                        );

                        ui.add_space(10.0_f32);
                        if ui.button("Close").clicked() {
                            keep_open = false;
                        }
                    });
            }
        }

        if let Some(next_dialog) = follow_up {
            self.dialog = Some(next_dialog);
        } else if keep_open {
            self.dialog = Some(dialog);
        }
    }
}

/// Renders the interactive 7x24 weekly logon hours editor inside the Edit User dialog.
fn render_logon_hours_editor(
    ui: &mut Ui,
    hours: &mut LogonHours,
    tz_offset: i32,
    palette: Palette,
) {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    ui.horizontal(|ui| {
        ui.label(format!(
            "Allowed hours: {}/168 (Local UTC{:+})",
            hours.allowed_hour_count(),
            tz_offset
        ));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.small_button("Deny All").clicked() {
                *hours = LogonHours::all_denied();
            }
            if ui.small_button("Mon-Fri 8 AM-5 PM").clicked() {
                hours.set_weekday_business_hours(tz_offset);
            }
            if ui.small_button("Allow All").clicked() {
                *hours = LogonHours::all_allowed();
            }
        });
    });
    ui.add_space(4.0_f32);
    ui.label(
        RichText::new(
            "Click any cell to toggle permitted logon hours (filled = allowed, empty = denied).",
        )
        .small()
        .color(palette.text_muted),
    );
    ui.add_space(4.0_f32);

    let cell_w = 20.0_f32;
    let cell_h = 20.0_f32;

    ui.horizontal(|ui| {
        ui.add_space(48.0_f32);
        for hour in (0..24).step_by(3) {
            let label = match hour {
                0 => "12a",
                12 => "12p",
                h if h < 12 => match h {
                    3 => "3a",
                    6 => "6a",
                    9 => "9a",
                    _ => "",
                },
                h => match h {
                    15 => "3p",
                    18 => "6p",
                    21 => "9p",
                    _ => "",
                },
            };
            ui.allocate_ui(Vec2::new(cell_w * 3.0_f32 + 4.0_f32, 18.0_f32), |ui| {
                ui.label(RichText::new(label).small().color(palette.text_muted));
            });
        }
    });

    for (day_idx, day_name) in DAYS.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0_f32;
            ui.allocate_ui(Vec2::new(44.0_f32, cell_h), |ui| {
                ui.label(*day_name);
            });
            for hour in 0..24 {
                let allowed = hours.is_local_hour_allowed(day_idx, hour, tz_offset);
                let (rect, resp) =
                    ui.allocate_exact_size(Vec2::new(cell_w, cell_h), Sense::click());
                let fill = if allowed {
                    palette.accent
                } else {
                    palette.bg_surface
                };
                ui.painter().rect_filled(rect, CornerRadius::same(2), fill);
                ui.painter().rect_stroke(
                    rect,
                    CornerRadius::same(2),
                    Stroke::new(1.0_f32, palette.border),
                    egui::StrokeKind::Inside,
                );
                if resp.clicked() {
                    hours.set_local_hour(day_idx, hour, !allowed, tz_offset);
                }
                let hour_12 = match hour {
                    0 => "12:00 AM".to_string(),
                    1..=11 => format!("{hour}:00 AM"),
                    12 => "12:00 PM".to_string(),
                    _ => format!("{}:00 PM", hour - 12),
                };
                resp.on_hover_text(format!(
                    "{day_name} {hour_12} - {}",
                    if allowed { "Allowed" } else { "Denied" }
                ));
            }
        });
    }
}

/// Sets or clears one bit inside a UF_* flags bitmask.
fn set_flag(flags: &mut u32, bit: u32, enabled: bool) {
    if enabled {
        *flags |= bit;
    } else {
        *flags &= !bit;
    }
}
