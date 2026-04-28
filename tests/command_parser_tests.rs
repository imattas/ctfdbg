use ctfdbg::commands::ast::Command;
use ctfdbg::commands::parser::parse_line;

fn p(s: &str) -> Command {
    parse_line(s).unwrap().expect("expected a command")
}

#[test]
fn parses_basic_commands() {
    assert_eq!(p("c"), Command::Continue);
    assert_eq!(p("continue"), Command::Continue);
    assert_eq!(p("si"), Command::StepInto);
    assert_eq!(p("n"), Command::StepOver);
    assert_eq!(p("regs"), Command::Regs);
    assert_eq!(p("checksec"), Command::Checksec);
    assert_eq!(p("quit"), Command::Quit);
}

#[test]
fn parses_break_with_address() {
    match p("b *0x401234") {
        Command::BreakAt(s) => assert!(s.contains("401234")),
        _ => panic!("expected BreakAt"),
    }
}

#[test]
fn parses_examine_x16gx() {
    match p("x/16gx 0x401000") {
        Command::Examine { count, format, address } => {
            assert_eq!(count, 16);
            assert_eq!(format, 'x');
            assert!(address.contains("401000"));
            // size suffix 'g' is consumed; we don't assert on it
        }
        _ => panic!("expected Examine"),
    }
}

#[test]
fn empty_and_comments() {
    assert!(parse_line("").unwrap().is_none() || matches!(parse_line("").unwrap(), Some(Command::Comment(_))));
    match parse_line("# hello").unwrap() {
        None => {}
        Some(Command::Comment(_)) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn parses_cyclic() {
    match p("cyclic 200") {
        Command::Cyclic(n) => assert_eq!(n, 200),
        _ => panic!("expected Cyclic"),
    }
}
