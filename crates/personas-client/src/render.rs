//! Badge images, for transports that can show one.
//!
//! Only Slack renders badges — it uploads a PNG alongside the message. Signal and the
//! serverless path carry the badge *proof* and nothing else, so this module (and the
//! SVG toolchain it drags in) is behind the `render` feature.

use anyhow::{anyhow, Context, Result};
use badge_maker::{BadgeBuilder, Style};
use resvg::{
    tiny_skia,
    usvg::{Options, Tree},
};
use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::Arc,
};

use crate::{badges::badge_name, PersonaClient};

/// A stable color per badge text, so "Faculty" always renders the same shade.
pub fn color_for_badge_text(text: &str) -> String {
    let mut hasher = DefaultHasher::new();
    text.to_lowercase().hash(&mut hasher);

    // Only the hue varies; fixing saturation and lightness keeps every badge legible.
    let hue = (hasher.finish() % 360) as f64;
    hsl_to_hex(hue, 0.55, 0.55)
}

fn hsl_to_hex(h: f64, s: f64, l: f64) -> String {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;

    let (r1, g1, b1) = match h {
        h if (0.0..60.0).contains(&h) => (c, x, 0.0),
        h if (60.0..120.0).contains(&h) => (x, c, 0.0),
        h if (120.0..180.0).contains(&h) => (0.0, c, x),
        h if (180.0..240.0).contains(&h) => (0.0, x, c),
        h if (240.0..300.0).contains(&h) => (x, 0.0, c),
        _ => (c, 0.0, x),
    };

    format!(
        "#{:02X}{:02X}{:02X}",
        ((r1 + m) * 255.0) as u8,
        ((g1 + m) * 255.0) as u8,
        ((b1 + m) * 255.0) as u8
    )
}

impl PersonaClient {
    /// Render badge slot `index` to SVG and PNG under the client's badge directory.
    pub fn render_badge(&self, index: u32) -> Result<PathBuf> {
        let text = badge_name(index);

        let svg = BadgeBuilder::new()
            .label("Badge")
            .message(text)
            .color_parse(&color_for_badge_text(text))
            .style(Style::Flat)
            .build()
            .map_err(|e| anyhow!("failed to build badge {index}: {e}"))?
            .svg();

        let dir = self.cfg.badge_dir();
        fs::create_dir_all(&dir)?;

        let svg_path = dir.join(format!("badge{index}.svg"));
        fs::write(&svg_path, &svg)
            .with_context(|| format!("failed to write {}", svg_path.display()))?;

        let png_path = dir.join(format!("badge{index}.png"));
        render_svg_to_png(&svg, &png_path)?;

        Ok(png_path)
    }

    /// The rendered PNG for badge slot `index`, ready to upload.
    pub fn badge_png(&self, index: u32) -> Result<Vec<u8>> {
        let path = self.cfg.badge_dir().join(format!("badge{index}.png"));
        fs::read(&path).with_context(|| {
            format!(
                "no rendered badge at {}; run a badge sync first",
                path.display()
            )
        })
    }
}

fn render_svg_to_png(svg: &str, out: &std::path::Path) -> Result<()> {
    let mut opt = Options::default();

    // badge-maker emits text, so the badge is blank without a font database.
    Arc::get_mut(&mut opt.fontdb)
        .ok_or_else(|| anyhow!("font database is shared and cannot be initialized"))?
        .load_system_fonts();

    let tree = Tree::from_str(svg, &opt).map_err(|e| anyhow!("badge SVG is invalid: {e}"))?;

    let size = tree.size();
    let mut pixmap = tiny_skia::Pixmap::new(size.width() as u32, size.height() as u32)
        .ok_or_else(|| anyhow!("badge has a degenerate size"))?;

    resvg::render(&tree, tiny_skia::Transform::identity(), &mut pixmap.as_mut());

    pixmap
        .save_png(out)
        .with_context(|| format!("failed to write {}", out.display()))?;

    Ok(())
}
