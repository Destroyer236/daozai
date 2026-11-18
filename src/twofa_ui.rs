//! 验证器页面（岛内）与设置里的管理入口。
//!
//! 岛内一屏最多显示 3 条，点任意一行复制动态码；更多账号左下角提示去设置里管理。
//! 密钥不在岛内出现，也不写进任何配置文件。

use crate::app::{App, Cmd, Env, TWOFA_H};
use crate::extras::{settings_card, settings_control_row, settings_hint, settings_label};
use crate::paint::{capsule, Card, H};
use crate::settings_theme::color as settings_color;
use crate::theme::{self, W};
use eframe::egui::{self, Color32};

const TWOFA_SETTINGS_TAB: usize = 13;
const ROW_H: f32 = 40.0;
const ROW_GAP: f32 = 6.0;

impl App {
    pub(crate) fn page_twofa(&mut self, c: &Card, _env: &Env, cmds: &mut Vec<Cmd>) {
        if self.twofa.accounts.is_empty() {
            // 空状态整块居中：文字与按钮都按面板中线摆放，垂直方向落在标题栏下方区域的中部。
            let center = crate::app::PW / 2.0;
            c.text(center, 95.0, "还没有两步验证账号", 13.0, W::Bold, theme::WHITE, H::Center);
            c.text(center, 113.0, "添加后在这里查看 6 位动态码，点击即复制", 10.5, W::Regular, theme::GRAY, H::Center);
            let (go, gc) = capsule(c, center - 46.0, 127.0, 92.0, 26.0, "twofa-setup", theme::BTN, theme::BTN_HOVER);
            gc.centered_text(center, 140.0, "添加账号", 11.0, W::Regular, theme::WHITE, H::Center);
            if go.clicked() {
                self.settings_tab = TWOFA_SETTINGS_TAB;
                self.open_settings();
            }
            return;
        }

        let total = self.twofa.accounts.len();
        let shown = total.min(3);
        // 动态码必须按真实时钟算，不能用 `env.t`（那是本次运行的秒数）。
        let at = self.twofa_clock.unwrap_or_else(crate::twofa::now);
        for index in 0..shown {
            let account = self.twofa.accounts[index].clone();
            let y = 36.0 + index as f32 * (ROW_H + ROW_GAP);
            let code = self.twofa.code(&account, at);
            c.fill(38.0, y, 343.0, ROW_H, 9.0, theme::CARD);
            let code_text = code.as_ref().ok().map(|code| crate::twofa::display(code));
            let code_w = code_text.as_ref().map(|text| c.text_w(text, 17.0, W::Semibold)).unwrap_or(0.0);
            let title = c.fit(account.title(), 12.0, W::Semibold, 326.0 - code_w);
            c.text(50.0, y + 16.0, &title, 12.0, W::Semibold, theme::WHITE, H::Left);
            if !account.subtitle().is_empty() {
                c.text(50.0, y + 30.0, &c.fit(account.subtitle(), 10.0, W::Regular, 230.0), 10.0, W::Regular, theme::GRAY, H::Left);
            }
            match &code {
                Ok(code) => {
                    let (_, left_seconds) = crate::twofa::window(at);
                    let left = (left_seconds / crate::twofa::PERIOD as f64) as f32;
                    c.fill(40.0, y + ROW_H - 2.0, 339.0 * left, 1.5, 0.75, Color32::from_rgb(64, 120, 220));
                    c.text(372.0, y + 22.0, &crate::twofa::display(code), 17.0, W::Semibold, theme::GREEN, H::Right);
                    let hit = c.hit(38.0, y, 343.0, ROW_H, ("twofa-row", &account.id)).on_hover_text(format!("复制 {} 的动态码", account.title()));
                    if hit.clicked() {
                        cmds.push(Cmd::Copy(code.clone()));
                        self.say("已复制动态码");
                    }
                }
                Err(reason) => {
                    c.text(372.0, y + 20.0, "无法生成", 11.0, W::Regular, Color32::from_rgb(255, 166, 77), H::Right);
                    let hit = c.hit(38.0, y, 343.0, ROW_H, ("twofa-row", &account.id)).on_hover_text(reason.clone());
                    if hit.clicked() {
                        self.settings_tab = TWOFA_SETTINGS_TAB;
                        self.open_settings();
                    }
                }
            }
        }
        if total > shown {
            let y = 36.0 + shown as f32 * (ROW_H + ROW_GAP) + 4.0;
            let text = format!("另有 {} 个账号，点这里管理", total - shown);
            c.text(42.0, y + 8.0, &text, 10.5, W::Regular, theme::DIM, H::Left);
            if c.hit(38.0, y, 343.0, 16.0, "twofa-more").clicked() {
                self.settings_tab = TWOFA_SETTINGS_TAB;
                self.open_settings();
            }
        } else {
            c.text(42.0, TWOFA_H - 10.0, "每 30 秒自动更新 · 点击复制", 10.0, W::Regular, theme::DIM, H::Left);
        }
    }

    pub(crate) fn twofa_settings(&mut self, ui: &mut egui::Ui) {
        let ctx = &ui.ctx().clone();
        settings_label(ui, "已添加的验证器");
        settings_card(ui, |ui| {
            if self.twofa.accounts.is_empty() {
                ui.label(egui::RichText::new("还没有验证器。在下面手动添加，或粘贴 otpauth 链接导入。").size(12.0).color(settings_color(ctx, Color32::from_gray(195), Color32::from_gray(60))));
            }
            let mut remove = None;
            let total = self.twofa.accounts.len();
            for index in 0..total {
                if index > 0 {
                    ui.separator();
                }
                let account = self.twofa.accounts[index].clone();
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(account.title()).size(13.0).color(settings_color(ctx, Color32::WHITE, Color32::from_rgb(30, 34, 41))));
                        if !account.subtitle().is_empty() {
                            ui.label(egui::RichText::new(account.subtitle()).size(11.5).color(settings_color(ctx, Color32::from_gray(180), Color32::from_gray(75))));
                        }
                        let saved = self.twofa.secret(&account.id).is_some();
                        ui.label(egui::RichText::new(if saved { "密钥已保存在系统凭据管理器" } else { "本机缺少这条密钥，请删除后重新添加" }).size(11.0).color(if saved { settings_color(ctx, Color32::from_rgb(120, 210, 160), Color32::from_rgb(24, 120, 80)) } else { settings_color(ctx, Color32::from_rgb(235, 180, 90), Color32::from_rgb(150, 90, 20)) }));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add_sized([60.0, 26.0], egui::Button::new("删除")).clicked() {
                            remove = Some(index);
                        }
                    });
                });
            }
            if let Some(index) = remove {
                let title = self.twofa.accounts[index].title().to_string();
                self.twofa.remove(index);
                self.twofa_form.note = format!("{title}：已删除，密钥已从系统凭据管理器移除");
            }
            settings_hint(ui, "密钥只进 Windows 凭据管理器，设置文件里只有名称和账号；换电脑后需要重新添加。");
        });

        settings_label(ui, "手动添加");
        settings_card(ui, |ui| {
            settings_control_row(ui, "服务名", 64.0, |ui| ui.add(egui::TextEdit::singleline(&mut self.twofa_form.issuer).vertical_align(egui::Align::Center).hint_text("例如 GitHub、Microsoft")));
            settings_control_row(ui, "账号", 64.0, |ui| ui.add(egui::TextEdit::singleline(&mut self.twofa_form.label).vertical_align(egui::Align::Center).hint_text("例如邮箱、用户名")));
            settings_control_row(ui, "密钥", 64.0, |ui| {
                let field = ui.add(egui::TextEdit::singleline(&mut self.twofa_form.secret).vertical_align(egui::Align::Center).password(!self.twofa_form.show_secret).hint_text("Base32 密钥，可带空格"));
                if ui.button(if self.twofa_form.show_secret { "隐藏" } else { "显示" }).clicked() {
                    self.twofa_form.show_secret = !self.twofa_form.show_secret;
                }
                field
            });
            ui.horizontal(|ui| {
                if ui.button("保存并开始验证").clicked() {
                    let (issuer, label, secret) = (self.twofa_form.issuer.clone(), self.twofa_form.label.clone(), self.twofa_form.secret.clone());
                    match self.twofa.add(&issuer, &label, &secret) {
                        Ok(()) => {
                            self.twofa_form.issuer.clear();
                            self.twofa_form.label.clear();
                            self.twofa_form.secret.clear();
                            self.twofa_form.note = format!("已添加 {}，岛上的验证器页面立即显示动态码", if issuer.trim().is_empty() { label.trim() } else { issuer.trim() });
                        }
                        Err(error) => self.twofa_form.note = error,
                    }
                }
                ui.label(egui::RichText::new("支持 6 位、30 秒一步的 SHA1 动态码").size(11.0).color(settings_color(ctx, Color32::from_gray(175), Color32::from_gray(90))));
            });
        });

        settings_label(ui, "从 otpauth 链接导入");
        settings_card(ui, |ui| {
            ui.add(egui::TextEdit::singleline(&mut self.twofa_form.uri).vertical_align(egui::Align::Center).hint_text("otpauth://totp/发行方:账号?secret=…"));
            ui.horizontal(|ui| {
                if ui.button("导入").clicked() {
                    let uri = self.twofa_form.uri.clone();
                    match self.twofa.add_uri(&uri) {
                        Ok(()) => {
                            self.twofa_form.uri.clear();
                            self.twofa_form.note = "已从链接导入，密钥保存在系统凭据管理器".into();
                        }
                        Err(error) => self.twofa_form.note = error,
                    }
                }
                ui.label(egui::RichText::new("验证器 App 一般都能导出这种链接；只支持 SHA1 / 6 位 / 30 秒").size(11.0).color(settings_color(ctx, Color32::from_gray(175), Color32::from_gray(90))));
            });
        });

        if !self.twofa_form.note.is_empty() {
            settings_hint(ui, &self.twofa_form.note);
        }
    }
}
