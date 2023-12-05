use cursive::{
    align::HAlign,
    theme::Color,
    view::{Nameable, Resizable},
    views::{Dialog, EditView, LinearLayout, ListView, TextView},
    Cursive,
};
use cursive_spinner_view::{Frames, SpinnerView};
use std::{
    env::temp_dir,
    str::FromStr,
    sync::{Arc, Mutex},
};
use std::{path::PathBuf, thread};

use crate::{proving, PerfResult, ProvingArgs, RandomXMode, TuiArgs, pow, PowPerfResult, PowArgs, parse_difficulty};

pub const DOTS: Frames = &[
    "⢀⠀", "⡀⠀", "⠄⠀", "⢂⠀", "⡂⠀", "⠅⠀", "⢃⠀", "⡃⠀", "⠍⠀", "⢋⠀", "⡋⠀", "⠍⠁", "⢋⠁", "⡋⠁", "⠍⠉", "⠋⠉",
    "⠋⠉", "⠉⠙", "⠉⠙", "⠉⠩", "⠈⢙", "⠈⡙", "⢈⠩", "⡀⢙", "⠄⡙", "⢂⠩", "⡂⢘", "⠅⡘", "⢃⠨", "⡃⢐", "⠍⡐", "⢋⠠",
    "⡋⢀", "⠍⡁", "⢋⠁", "⡋⠁", "⠍⠉", "⠋⠉", "⠋⠉", "⠉⠙", "⠉⠙", "⠉⠩", "⠈⢙", "⠈⡙", "⠈⠩", "⠀⢙", "⠀⡙", "⠀⠩",
    "⠀⢘", "⠀⡘", "⠀⠨", "⠀⢐", "⠀⡐", "⠀⠠", "⠀⢀", "⠀⡀",
];

#[derive(Clone, Debug)]
#[derive(Default)]
struct UserData {
    proving: ProvingData,
    pow: PowData,
}


#[derive(Clone, Debug)]
struct ProvingData {
    data_file: PathBuf,
    data_size: u64,
    duration: u64,
    threads: usize,
    nonces: u32,
}

#[derive(Clone, Debug)]
struct PowData {
    iterrations: usize,
    threads: usize,
    nonces: u32,
    num_units: u32,
    difficulty: String,
    randomx_mode: RandomXMode,
}

impl Default for ProvingData {
    fn default() -> Self {
        ProvingData {
            data_file: temp_dir().join("profiler_data.bin"),
            data_size: 1,
            duration: 10,
            threads: 4,
            nonces: 64,
        }
    }
}

impl Default for PowData {
    fn default() -> Self {
        PowData {
            iterrations: 5,
            threads: 4,
            nonces: 64,
            num_units: 4,
            difficulty: "000dfb23b0979b4b000000000000000000000000000000000000000000000000"
                .to_string(),
            randomx_mode: RandomXMode::Fast,
        }
    }
}

pub fn start_tui(_args: TuiArgs) -> eyre::Result<()> {
    let mut siv = cursive::default();
    siv.set_user_data(UserData::default());

    siv.add_layer(
        Dialog::text("Spacemesh Profiler")
            .title("Spacemesh Profiler")
            .button("K2 PoW profile", |s| {
                let current_data = s
                    .with_user_data(|user_data: &mut UserData| user_data.clone())
                    .unwrap();
                s.add_layer(
                    Dialog::new()
                        .title("K2 PoW profile settings")
                        .content(
                            ListView::new()
                                .child(
                                    "Iterrations: ",
                                    EditView::new()
                                        .content(current_data.pow.iterrations.to_string().clone())
                                        .with_name("iterrations")
                                        .fixed_width(64),
                                )
                                .child(
                                    "Threads: ",
                                    EditView::new()
                                        .content(current_data.pow.threads.to_string().clone())
                                        .with_name("threads")
                                        .fixed_width(64),
                                )
                                .child(
                                    "Nonces: ",
                                    EditView::new()
                                        .content(current_data.pow.nonces.to_string().clone())
                                        .with_name("nonces"),
                                )
                                .child(
                                    "Num units: ",
                                    EditView::new()
                                        .content(current_data.pow.num_units.to_string().clone())
                                        .with_name("num_units"),
                                )
                                .child(
                                    "Difficulty: ",
                                    EditView::new()
                                        .content(current_data.pow.difficulty.to_string().clone())
                                        .with_name("difficulty"),
                                )
                                .child(
                                    "RandomXMode: ",
                                    EditView::new()
                                        .content(current_data.pow.randomx_mode.to_string().clone())
                                        .with_name("randomx_mode"),
                                ),
                        )
                        .button("Done", move |s| {
                            let iterrations = s
                                .call_on_name("iterrations", |view: &mut EditView| {
                                    view.get_content().parse::<usize>().unwrap_or(5)
                                })
                                .unwrap();

                            let threads = s
                                .call_on_name("threads", |view: &mut EditView| {
                                    view.get_content().parse::<usize>().unwrap_or(1)
                                })
                                .unwrap();

                            let nonces = s
                                .call_on_name("nonces", |view: &mut EditView| {
                                    view.get_content().parse::<u32>().unwrap_or(64)
                                })
                                .unwrap();

                            let num_units = s
                                .call_on_name("num_units", |view: &mut EditView| {
                                    view.get_content().parse::<u32>().unwrap_or(4)
                                })
                                .unwrap();

                            let difficulty = s
                                .call_on_name("difficulty", |view: &mut EditView| {
                                    view.get_content().parse::<String>().unwrap_or("d000dfb23b0979b4b000000000000000000000000000000000000000000000000".to_string())
                                })
                                .unwrap();

                            let randomx_mode = s
                                .call_on_name("randomx_mode", |view: &mut EditView| {
                                    view.get_content().parse::<String>().unwrap_or("fast".to_string())
                                })
                                .unwrap();


                            let mode = match randomx_mode.as_str() {
                                "fast" => RandomXMode::Fast,
                                "light" => RandomXMode::Light,
                                _ => RandomXMode::Fast
                            };

                            let data = UserData {
                                pow: PowData {
                                    iterrations,
                                    threads,
                                    nonces,
                                    num_units,
                                    difficulty,
                                    randomx_mode: mode
                                },
                                ..Default::default()
                            };     

                            s.set_user_data(data.clone());

                            s.pop_layer();

                            let cb = s.cb_sink().clone();

                            let proving_args_arc = Arc::new(Mutex::new(data));
                            thread::spawn(move || {
                                let data = proving_args_arc.lock().unwrap();
                                let result = pow(PowArgs {
                                    iterations: data.pow.iterrations,
                                    threads: data.pow.threads,
                                    nonces: data.pow.nonces,
                                    num_units: data.pow.num_units,
                                    difficulty: parse_difficulty(data.pow.difficulty.as_str()).unwrap(),
                                    randomx_mode: data.pow.randomx_mode
                                }          
                                )
                                .unwrap();

                                cb.send(Box::new(|s| powperf_result_view(s, result))).unwrap();
                            });
                            let mut spinner = SpinnerView::new(s.cb_sink().clone());

                            spinner.spin_up();
                            spinner.frames(DOTS);
                            spinner.style(Color::parse("black").unwrap());

                            s.add_layer(
                                Dialog::new()
                                    .content(
                                        LinearLayout::horizontal()
                                            .child(spinner)
                                            .child(TextView::new(" Running K2 PoW profiler...")),
                                    )
                                    .h_align(HAlign::Center)
                                    .min_width(40)
                                    .min_height(10),
                            );
                        }),
                );
            })
            .button("Proving profile", |s| {
                let current_data = s
                    .with_user_data(|user_data: &mut UserData| user_data.clone())
                    .unwrap();
                s.add_layer(
                    Dialog::new()
                        .title("Proving profile settings")
                        .content(
                            ListView::new()
                                .child(
                                    "Data file path: ",
                                    EditView::new()
                                        .content(
                                            current_data
                                                .proving
                                                .data_file
                                                .to_string_lossy()
                                                .clone(),
                                        )
                                        .with_name("data_file")
                                        .fixed_width(64),
                                )
                                .child(
                                    "Data size (GiB): ",
                                    EditView::new()
                                        .content(current_data.proving.data_size.to_string().clone())
                                        .with_name("data_size"),
                                )
                                .child(
                                    "Duration (s): ",
                                    EditView::new()
                                        .content(current_data.proving.duration.to_string().clone())
                                        .with_name("duration"),
                                )
                                .child(
                                    "Threads: ",
                                    EditView::new()
                                        .content(current_data.proving.threads.to_string().clone())
                                        .with_name("threads"),
                                )
                                .child(
                                    "Nonces: ",
                                    EditView::new()
                                        .content(current_data.proving.nonces.to_string().clone())
                                        .with_name("nonces"),
                                ),
                        )
                        .button("Done", move |s| {
                            let data_file = s
                                .call_on_name("data_file", |view: &mut EditView| {
                                    view.get_content().parse::<String>().unwrap_or(
                                        temp_dir()
                                            .join("profile_data.bin")
                                            .into_os_string()
                                            .into_string()
                                            .unwrap(),
                                    )
                                })
                                .unwrap();

                            let data_size = s
                                .call_on_name("data_size", |view: &mut EditView| {
                                    view.get_content().parse::<u64>().unwrap_or(1)
                                })
                                .unwrap();

                            let duration = s
                                .call_on_name("duration", |view: &mut EditView| {
                                    view.get_content().parse::<u64>().unwrap_or(10)
                                })
                                .unwrap();

                            let threads = s
                                .call_on_name("threads", |view: &mut EditView| {
                                    view.get_content().parse::<usize>().unwrap_or(4)
                                })
                                .unwrap();

                            let nonces = s
                                .call_on_name("nonces", |view: &mut EditView| {
                                    view.get_content().parse::<u32>().unwrap_or(64)
                                })
                                .unwrap();

                            let data = UserData {
                                proving: ProvingData {
                                    data_file: PathBuf::from_str(data_file.as_str()).unwrap(),
                                    data_size,
                                    duration,
                                    threads,
                                    nonces,
                                },
                                ..Default::default()
                            };

                            s.set_user_data(data.clone());

                            s.pop_layer();

                            let cb = s.cb_sink().clone();

                            let proving_args_arc = Arc::new(Mutex::new(data));
                            thread::spawn(move || {
                                let data = proving_args_arc.lock().unwrap();
                                let result = proving(ProvingArgs {
                                    data_file: Some(data.proving.data_file.clone()),
                                    data_size: data.proving.data_size,
                                    duration: data.proving.duration,
                                    threads: data.proving.threads,
                                    nonces: data.proving.nonces,
                                })
                                .unwrap();

                                cb.send(Box::new(|s| perf_result_view(s, result))).unwrap();
                            });
                            let mut spinner = SpinnerView::new(s.cb_sink().clone());

                            spinner.spin_up();
                            spinner.frames(DOTS);
                            spinner.style(Color::parse("black").unwrap());

                            s.add_layer(
                                Dialog::new()
                                    .content(
                                        LinearLayout::horizontal()
                                            .child(spinner)
                                            .child(TextView::new(" Running proving profiler...")),
                                    )
                                    .h_align(HAlign::Center)
                                    .min_width(40)
                                    .min_height(10),
                            );
                        }),
                );
            }),
    );

    siv.run();
    Ok(())
}

fn perf_result_view(s: &mut Cursive, result: PerfResult) {
    s.set_autorefresh(false);
    s.pop_layer();
    s.add_layer(
        Dialog::new()
            .title("Proving profiling complete")
            .content(TextView::new(format!("Results: \n\n Time (s): {:?} \n Speed (GiB): {:?}", result.time_s, result.speed_gib_s)).center())
            .button("Quit", |s| s.quit()),
    );
}
fn powperf_result_view(s: &mut Cursive, result: PowPerfResult) {
    s.set_autorefresh(false);
    s.pop_layer();
    s.add_layer(
        Dialog::new()
            .title("K2 PoW profiling complete")
            .content(TextView::new(format!("Results: \n\n Iterrations: {:?} \n RandomX VM Init time (s): {:?} \n Average Time (s): {:?}", result.iterations, result.randomx_vm_init_time, result.average_time)).center())
            .button("Quit", |s| s.quit()),
    );
}
