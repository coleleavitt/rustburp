use colored::Colorize;

/// Print the cool ASCII banner
pub fn print_banner() {
    // Hand-crafted ASCII art for better control
    let banner = r#"
    ██████╗ ██╗   ██╗███████╗██████╗ ██╗   ██╗██████╗ ██████╗ 
    ██╔══██╗██║   ██║██╔════╝██╔══██╗██║   ██║██╔══██╗██╔══██╗
    ██████╔╝██║   ██║███████╗██████╔╝██║   ██║██████╔╝██████╔╝
    ██╔══██╗██║   ██║╚════██║██╔══██╗██║   ██║██╔══██╗██╔═══╝ 
    ██║  ██║╚██████╔╝███████║██████╔╝╚██████╔╝██║  ██║██║     
    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     
    "#;

    // Print with gradient effect (orange to red)
    for (i, line) in banner.lines().enumerate() {
        let colored_line = match i % 6 {
            0 => line.truecolor(255, 100, 0), // Orange
            1 => line.truecolor(255, 80, 0),
            2 => line.truecolor(255, 60, 0),
            3 => line.truecolor(255, 40, 20),
            4 => line.truecolor(255, 20, 40),
            _ => line.truecolor(255, 0, 60), // Red
        };
        println!("{}", colored_line);
    }

    println!(
        "    {} {} | {} {}",
        "v".dimmed(),
        env!("CARGO_PKG_VERSION").yellow(),
        "Burp Suite Pro License Manager".dimmed(),
        "by Zer0DayLab".truecolor(100, 100, 100)
    );
    println!();
}

/// Print a smaller inline banner for subcommands
#[allow(dead_code)]
pub fn print_mini_banner() {
    println!(
        "{} {} {}",
        "rusburp".truecolor(255, 100, 0).bold(),
        "v".dimmed(),
        env!("CARGO_PKG_VERSION").yellow()
    );
}
