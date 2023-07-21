# What is the profiler tool

The major goal of profiler tool is to provide an estimation how fast can be the proof created.
Creating a proof in spacemesh depends on few major factors:
* CPU speed
* Disk speed
* Amount of storage initialized

The primary goal of the profiler tool is to estimate how fast a PoST proof can be created for a given CPU and disk speed.

The best way to get the profiler tool is to get it from the [releases page](https://github.com/spacemeshos/post-rs/releases).

It's important to understand that the proving time itself does not need to be optimized. It's enough to generate proof in a specified time window, which on the mainnet is 12h.

## How to run profiler tool

For accurate results set the path with `--data-file` to the same disk that will be used by the node, otherwise the results of the benchmark might not reflect the actual performance of the node. Please be warned that the contents of that file MIGHT be overwritten.

By default the profiler uses 1GiB sample data. This can be changed with the `--data-size` flag. Different sizes can be used to check for bottlenecks of the hardware.

The duration of the benchmark can be set with `--duration` and defaults to 10 seconds. A longer duration will yield more accurate results.

There are two parameters that can influence the proofing speed and can be optimized for go-spacemesh: `--threads` and `--nonces`.
The general rule of thumb is the more threads the faster, but because different processors may have different behaviours when all threads are under load. Please check different values for `--threads` to find the optimal one.
The more nonces are used with `--nonces` in ONE data pass, the bigger the chance to find a valid proof. The downside of using more `--nonces` is a heavier load on the CPU.

To simplify the estimation of nonces please use the following formula:
in google sheets format
```
1-(1-(1-BINOM.DIST(36;10^9;26/10^9;TRUE)))^{put nonces here}
```
in wolfram alpha format
```
1-(1-(1-CDF[BinomialDistribution[10^9, 26/10^9],36]))^{put nonces here}
```

This formula gives the probability of finding a valid proof in one data pass. The node will perform multiple passes if needed.

Please note that proving speed linearly scales with the number of cores used (assuming that they're equally fast), but inversely scales with the number of nonces in groups of 16 (32 nonces should be twice as slow as 16). This effect might not manifest itself until a high number of nonces is used. The reason is that in most setups the hard disk speed will be the limiting factor if a low number of nonces is used.

## How to interpret the results

```
./profiler --data-size 1 --threads=1 --data-file data.bin --nonces=64
{
  "time_s": 12.09140029,
  "speed_gib_s": 0.41351703525481415
}
```

Here we see the following
* 1GiB file `data.bin` was used for the benchmark
* 1 thread was used
* 64 nonces were used

The benchmark took 12.09 seconds to complete and the speed was 0.41GiB/s.
From the formula above we know that the probability of finding a proof with 64 nonces is 79.39%. Therefore there is a ~20% chance that at least two passes are necessary (and a ~ 0.20^x chance that more than x passes are necessary).
```
./profiler --data-size 1 --threads=1 --data-file data.bin --nonces=128
{
  "time_s": 13.152850458,
  "speed_gib_s": 0.22808744078552953
}
```

We see here that the speed dropped by half. That clearly indicates that CPU is our limiting factor.

With 128 nonces there is 95.75% chance to find a proof in one data pass.

```
./profiler --data-size 1 --threads=10 --data-file data.bin --nonces=128
{
  "time_s": 10.331206291,
  "speed_gib_s": 1.8390882405040923
}
```

With 10 threads we can see that speed increased by 8 times. It is important to optimize for the probability of finding a proof in time rather than optimizing for the speed. On mainnet nodes have a 12 hour window to find and submit a proof.

Based on these outputs you need to decide what is the best configuration for your hardware. Please note that the speed of the proof generation is not the only factor.

## Is that all that is happening during the proof generation?
Additionally for every group of 16 nonces there is an additional computation - often referred to as `k2pow` - required. It serves as mitigation against some possible attacks by dishonest smeshers.

Plaese add that time to the final time needed to generate a proof.

# Tips & Hints

### How to see that CPU is my limiting factor?
If `speed_gib_s` is slowing down with more noces, then CPU is most likely the limiting factor. Try to add more threads IF needed

### How to see that disk is my limiting factor?
If `speed_gib_s` is not slowing down with more nonces, then disk is most likely the limiting factor. Try to add more nonces IF needed. That should put more load on CPU and limit the probability of reading the data again from the disk.

### How do I find the sweet spot?
That depends, if you want to generate proof as fast as possible because you cannot have your computer working for 12hours then make it work as hard as possible regardless of anything else.

The general rule of thumb is that you want to match your disk speed with that benchmark. If your disk will be faster then CPU will be working on 100% and disk will NOT be fully utilized, if your CPU is faster than your HDD then the CPU will be waiting for the data from the disk.

### Do I need to finish the proof asap?
No, the proof needs to be done within a time window. On the mainnet that time window is 12hours. As long as you're able to generate a proof with high probability within this time, you are good.

### Can I really use whole 12hours?
Yes, you can, but please be warned that if you're using the whole 12hours then you're risking that you will not be able to submit the proof in time. Not submitting a proof means skipping an epoch (2 weeks on the mainnet). Please leave some buffer for occasional slowdowns on your side.


## How to use the values

```
"smeshing-proving-opts": {
  "smeshing-opts-proving-nonces": 144,
  "smeshing-opts-proving-threads": 0
},
```

Place that in your node config under `smeshing` key. Please note that the values are just an example and you need to use your own values. This is a `json` file so please make sure that it's formatted properly.

If you're using `smapp` then please put it to the node custom config file named `node-config.7c8cef2b` in Spacemesh app directory.
