# What is the profiler tool

The primary aim of the profiler tool is to provide an estimation of how fast can the [Proof of Space-Time (PoST)](https://docs.spacemesh.io/docs/learn/post) be [generated](https://docs.spacemesh.io/docs/learn/post#generating-the-proof) given existing [Proof of Space (PoS)](https://docs.spacemesh.io/docs/learn/post#proof-of-space) data. Generating the PoST in Spacemesh depends on a few major factors:

* CPU speed
* Disk speed
* Amount of storage initialized/ size of the PoS data (i.e., how much space one allocates to [smeshing](https://docs.spacemesh.io/docs/start/smeshing/start#what-is-smeshing))

Thus, the profiler tool can help a smesher:

* estimate how much storage one can safely initialize (to be able to generate a proof later).
* configure the proving process (by setting the desired number of CPU threads and [nonce](https://docs.spacemesh.io/docs/learn/post#generating-the-proof) count) optimally for the best use of the available resources.

## Downloading the profiler tool

The profiler tool can be downloaded from the [releases page](https://github.com/spacemeshos/post-rs/releases) of the [`post-rs`](https://github.com/spacemeshos/post-rs) repository. The download is located in the "Assets" section of the release page and will be visible after expanding this section by clicking on its title. The exact file to be downloaded for the different operating systems is as follows:

* `profiler-linux-vX.X.X.zip` for Linux (Ubuntu or Fedora, x86)
* `profiler-linux-arm64-vX.X.X.zip` for Linux (Ubuntu or Fedora, Arm-based)
* `profiler-macos-m1-vX.X.X.zip` for macOS (M1-based)
* `profiler-macos-vX.X.X.zip` for macOS (Intel-based)
* `profiler-windows-vX.X.X.zip` for Windows (x86)

It is important to understand that the proving time itself does not need to be optimized. It's enough to generate proof in a specified time window, which on the mainnet is 12 hours.

## Running the profiler tool

This section will guide you on how to extract and run the profiler tool on different operating systems. Once the appropriate `.zip` file is downloaded, follow the steps below to run the tool:

### Linux/macOS

1. Extract the contents of the `.zip` file somewhere. The extracted contents will include a singular script file called `profiler`.
2. Make the `profiler` file executable by opening a terminal in the directory where the file has been extracted and entering this command: `chmod +x profiler`.
3. Open the terminal once again and run the executable file that has just been created by entering this command: `./profiler`.

### Windows

1. Extract the contents of the `.zip` file somewhere. The extracted contents will include a singular script file called `profiler.exe`.
Open a Windows Powershell terminal in the directory where the file has been extracted. You can do this by holding the "shift" key, right-clicking, and selecting the "Open Powershell here" option.
2. In the Powershell terminal, enter this command to run the profiler tool: `./profiler`.

Having run the tool, one may wonder, what does the output mean? Read on to understand the various input flags one can use to customize each profiler run and how to interpret the subsequent results.

## Understanding the options and commands

When running the profiler tool, you can provide several inputs to it. This section goes over the various commands and options for the profiler tool and what they mean.

### Commands

* `proving`: We are telling the profiler to benchmark the entire PoST generation process.
* `pow:`: We are telling the profiler to only benchmark the Proof of Work (PoW) part of the PoST generation. More on this below.

If no command is given, the profiler runs the `proving` command by default.

### Options

* `--help`: Displays all the available commands and options along with their short descriptions. Use the `-h` flag for summarized help information.
* `--data-file` (path): This is the path to an existing PoS file that we have already generated as a smesher during the [initialization or PoS generation](https://docs.spacemesh.io/docs/learn/post#generating-the-data) phase. By providing the path to an existing PoS data file, we are asking the profiler how long will it take to generate the PoST with the given PoS data. For accurate results, it is recommended to use the exact PoS data file on the same disk as used by the smeshing node. However, do note that the contents of the data file might get overwritten by the profiler tool.
  * **Default**: The profiler tool will generate a 1 GiB PoS data file in a temporary directory.
* `--data-size` (size in GiB): This is the size (in GiB) of the PoS data that we want the profiler to estimate the PoST generation time for. For example, we can provide a value of 5 GiB to have the profiler estimate the time it takes to generate the PoST given 5 GiB of PoS data.
  * **Default**: A PoS data size of 1 GiB will be used for running the benchmark.
* `--duration` (in seconds): Duration in seconds of how long the profiler should run the PoST generation benchmark for. Longer duration yields more accurate results.
  * **Default**: 10 seconds.
* `--threads` (count): Number of CPU threads that will be used to run the benchmark. Generally, more threads mean faster PoST generation and lesser generation time. However, different CPUs behave differently when all threads are under load. Thus, keep experimenting with different values for `--threads` (with the maximum being the number of threads your CPU has) to find the optimal thread count.
  * **Default**: 4 threads.
* `--nonces` (count, multiple of 16): The amount of nonces to use in the proof of work calculation in one pass over the PoS data. Read [this section](https://docs.spacemesh.io/docs/learn/post#generating-the-proof) of the PoST explainer to understand how nonces are used in the PoST generation process. The greater the `--nonces` value, the more nonces are used in each data pass, increasing the chance of finding the PoST sooner and in lesser data passes. Note that whatever the number value used for `--nonces`, it must be a multiple of 16. One thing to be aware of when setting `--nonces` is that the higher the value used, the more stress the CPU will be under as this part of the PoST generation process is CPU-intensive.
  * **Default**: 64 nonces.

#### Nonce estimation formula

To help us estimate the value of `--nonces` that will help find the PoST in the least number of passes, the following formula, given in two prominent formats for ease of calculation, can be used:

**Google Sheets format**:
```
1-(1-(1-BINOM.DIST(36;10^9;26/10^9;TRUE)))^{put nonces value here}
```
**Wolfram Alpha format**:
```
1-(1-(1-CDF[BinomialDistribution[10^9, 26/10^9],36]))^{put nonces value here}
```

The aforementioned formula gives the probability (with an output of 1 being 100%) of finding a valid PoST in one data pass. The node will perform multiple passes if PoST is not found in one data pass.

Please note that PoST generation speed scales *linearly* with the number of CPU cores used (assuming that they are equally fast) and *inversely* with the number of nonces in groups of 16 (32 nonces should be twice as slow as 16). This effect might not manifest itself until a high number of nonces is used. The reason for this is that in most setups, the hard disk drive (HDD) speed will become the limiting factor (as a spinning disk drive is used in most computers) if a low number of nonces is used.

So, if we increase the CPU cores, the faster a valid PoST will be generated. And if you increase the number of nonces, the slower a valid PoST will be generated due to the increased usage of the HDD which results in the HDD speed being the limiting factor. Knowing this will help you make a better assessment of the profiler tool flags and its output.

## How to interpret the profiler output

We will now understand how to interpret the profiler output. Let us run the following command (for reference, all commands are being run on a 2020 MacBook Air M1 16GB/256GB):

```
./profiler --threads=1
```

In the above terminal command, we are running the profiler in `proving` mode and have provided the following options:

* The number of threads to be used is 1 (instead of the default 4).
* For all other options, default values (e.g., 64 for nonces) are to be used ([see above](#understanding-the-options-and-commands)).

After running this command, we get the following output:

```bash
{
  "time_s": 10.316020166,
  "speed_gib_s": 0.19387321542775668
}
```

The output means that it took 10.31 seconds to find a valid PoST and the speed was 0.19 GiB/s.
From the [formula above](#nonce-estimation-formula), we know that the probability of finding a proof with 64 nonces is 79.39%. Therefore, there is a ~20% chance that at least two passes are necessary (and a ~ 0.20^x chance that more than x passes are necessary).

Let us run another command, this time with the nonce count doubled to 128:

```bash
./profiler --threads=1 --nonces=128
{
  "time_s": 16.450039208,
  "speed_gib_s": 0.12158025733016843
}
```

We see here that the speed dropped by about 37%, which indicates that CPU is our limiting factor since we put more load on the CPU by doubling the nonces but only using 1 CPU thread. Note that with 128 nonces, there is a 95.75% chance of finding a PoST in one data pass.

Let us run the profiler again, this time with 128 nonces but 10 threads:

```bash
./profiler --threads=10 --nonces=128
{
  "time_s": 11.323834001,
  "speed_gib_s": 0.6181651902864203
}
```

With 10 threads we can see that speed increased by ~400% (4x). It is important to always optimize for the probability of finding a proof quickly within the 12-hour PoST submission rather than optimizing for speed. Based on these outputs, you need to decide what is the best configuration for your particular system. Please note that the speed of the proof generation is not the only factor.

## What else happens during the PoST generation?

For every group of 16 nonces, there is an additional computation - often referred to as `k2pow` - that is performed during the PoST generation process. It serves as mitigation against some possible attacks by dishonest smeshers.

On the mainnet, each set of 16 nonces requires one `k2pow` computation. In the case of a low-end CPU with a hash rate of 500 h/s in the [RandomX benchmark](https://xmrig.com/benchmark), approximately 2 minutes and 30 seconds are needed to create a PoW for 4 SUs (a Space Unit on the mainnet equates to 64GiB) and 64 nonces (4xPoW). This processing time scales down linearly with the hash rate and it scales up linearly with the number of SUs. You may want to check the single and multi-core results from the RandomX benchmark for more details. Please add your estimate (number of SU x the result of the RandomX benchmark) to the total time needed to generate a proof.

## Benchmarking K2 PoW

The `profiler` allows benchmarking of the PoW computation speed. The profiler always executes PoW for 1 SU to speed up measurement and automatically scales up the result by the requested number of units.

To understand the inner mechanics of RandomX PoW, take a look at its [specification](https://github.com/tevador/RandomX/blob/master/doc/specs.md).

Refer to `profiler pow --help` to understand how to use the profiler to benchmark the `k2pow`. Most users will need to tweak three arguments:

* `--threads`,
* `--num-units`,
* `--nonces`

### Example

`profiler pow --nonces 288 --num-units 16 --iterations 10 --threads 2 --randomx-mode fast`

## Tips & Hints

### How to verify that the CPU is the limiting factor?

If `speed_gib_s` is slowing down as nonces are increased, then the CPU is most likely the limiting factor. Try to add more threads only if needed.

### How to verify that the HDD is the limiting factor?

If `speed_gib_s` is not slowing down with more nonces, then HDD is most likely the limiting factor. As stated earlier, try to add more nonces only if needed. Increasing nonces puts more load on CPU but increases the chances of finding the proof after only one pass over PoS data.

### How do I find the sweet spot?

That depends. If you want to generate a PoST as fast as possible because you cannot have your computer working for 12 hours, then make it work as hard as possible regardless of anything else.

The general rule of thumb is that you want to match your HDD speed with that benchmark. If your HDD is faster than the CPU, then the CPU will be under 100% utilization while the HDD will NOT be fully utilized. If your CPU is faster than your HDD then the CPU will be waiting for the data from the HDD.

### Do I need to finish finding the PoST ASAP?

No. The PoST needs to be done within a time window. On mainnet, this time window is 12 hours long. As long as you are able to generate a PoST with a high probability within this time, you are good. However, you should not wait until the very end of the window. Try to find and submit a PoST at your earliest convenience to avoid accidentally missing the time window and not being eligible for that epoch.

### Can I use the entire 12-hour window to submit the PoST?

Yes, you can. However, be warned that you should not wait until the very end of the window to submit the proof. Try to find and submit a PoST at your earliest convenience to avoid accidentally missing the time window and not being eligible for that epoch. Not submitting a proof during this window means skipping an epoch (2 weeks on the mainnet). **Please leave some buffer for occasional slowdowns or any other unforeseen circumstances on your side**.

## How to use the profiler output values?

Once you have found your perfect nonces and threads values, enter them in node config file. For example:

```JSON
"smeshing-proving-opts": {
  "smeshing-opts-proving-nonces": 144,
  "smeshing-opts-proving-threads": 10
},
```

Place that in your node config JSON file under `smeshing` key. Please note that the values are just an example and you need to use your own values. Node config is a `JSON` file so please make sure that the values are formatted properly.

For Smapp users, the node config file is titled: `node-config.7c8cef2b.json` and is located in the Spacemesh directory.
