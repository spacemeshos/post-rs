# What is the profiler tool

The major goal of profiler tool is to provide an estimation how fast can be the proof created.
Creating a proof in spacemesh depends on few major factors:
* CPU speed
* Disk speed
* Amount of storage initialized

The major task of the profiler tool is to estimate how fast can be the proof created for a given CPU speed and disk speed.

The best way to get the profiler tool is to get it from the [releases page](https://github.com/spacemeshos/post-rs/releases).

It's very important to remember that the proof time itself does not need to be optimized against, we just need to generate valid proof in time which on the mainnet is 12h.

## How to run profiler tool

One of the most important part is to set correct path to data file using `--data-file` flag. It's important to set it so the benchmark will use the proper disk(s). Plaese be warned that the contents of that file MIGHT be overwritten.

By default profiler uses 1GiB sample data you can change that using `--data-size` flag. One can experiment with different sizes to check for the bottlenecks in the hardware.

It's also important to give specific `--duration`, that defaults to 10 seconds. The longer the duration the more accurate the results will be.

Proving options. There are two important parameters that then are used by go-spacemesh directly during the proof generation. `--threads` and `--nonces`.
The general rule of thumb is the more threads the faster, but because different processors may have different behaviours when all threads are under load please check different values for `--threads` to find the optimal one.
`--nonces` The more nonces one does in ONE data pass, the bigger chance to find a proof. The downside is the more `--nonces` the more work CPU will need to do.

To simplify the estimation of nonces please use the following formula:
in google sheets format
```
1-(1-(1-BINOM.DIST(36;10^9;26/10^9;TRUE)))^{put nonces here}
```
in wolfram alpha format
```
1-(1-(1-CDF[BinomialDistribution[10^9, 26/10^9],36]))^{put nonces here}
```

That formula will output a probability of finding proof in one data pass. Proving part is written in a way that it will do multiple data passes IF needed.

Please note that in genreal proof speed should almost linearly scale up with the amount of cores (assuming that they're equally fast), but in the same time it will linearlly scale down with the amount of nonces in groups of 16 (32 nonces should be twice as slow as 16)

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
But from previous formula we know that the probability of finding a proof with 64 nonces is 79.39%. Therefore there is 20% chance that we will need to read the data again. Therefore the actual time can be significanly longer.
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

With 10 threads we can see that speed increased by 8 times. But again it's important to remember that we don't necessarily need to optimize for the speed, we need to optimize for the probability of finding a proof in time. There are 12 hours to find and submit proof.

Based on these outputs you need to decide what is the best configuration for your hardware. Please note that the speed of the proof generation is not the only factor.

## Is that all that is happening during the proof generation?
Actually no, there is one more item which is that for each group of 16 nonces there is computation required. That exists to prevent a certain kind of exploit where an adversary with cheap processing power can replace some storage with much more computation, we’ve introduced a small amount of additional computation to the PoST proving process making this attack too expensive to carry out.
There are plans to delegate that computation to other servers and pay a small fee for that. You can sometimes find it referred as `k2pow`.

But for now you can assume that for EACH group of 64nonces once per proof process the computation required
For a low-end CPU with hash rate of 500 in [RandomX benchmark](https://xmrig.com/benchmark) that it should take 2mins30seconds per 1Space Unit (1 Space Unit in mainnet is 64GiB). It scales linearly with the hash rate. Please consult single and multicore results from the benchmark.

Plaese add that time to the final time needed to generate a proof.

# Tips & Hints

### How to see that CPU is my limiting factor?
If `speed_gib_s` is slowing down with more noces, then CPU is most likely the limiting factor. Try to add more threads IF needed

### How to see that disk is my limiting factor?
If `speed_gib_s` is not slowing down with more nonces, then disk is most likely the limiting factor. Try to add more nonces IF needed. That should put more load on CPU and limit the probability of reading the data again from the disk.

### How do I find the sweet spot?
That depends, if you want to generate proof as fast as possible because you cannot have your computer working for 12hours then make it work as hard as possible regardless of anything else.

The general rule of thumb is that you want to match your disk speed with that benchmark. If your disk will be faster then CPU will be working on 100% and disk will NOT be fully utilized, if your CPU is way faster than HDD then CPU may be waiting for the data from the disk.

### Do I need to finish the proof asap?
No, you need to be in time, on the mainnet that time is 12hours. As long as you're on time you're good.

### Can I really use whole 12hours?
Yes, you can, but please be warned that if you're using the whole 12hours then you're risking that you will not be able to submit the proof in time. Not submitting a proof means skipping an epoch (2 weeks on the mainnet). Please leave some buffer for ocasional slowdowns on your side.


## How to use the values

```
"smeshing-proving-opts": {
  "smeshing-opts-proving-nonces": 144,
  "smeshing-opts-proving-threads": 0
},
```

Place that in your node config. Please note that the values are just an example and you need to use your own values.

If you're using `smapp` then please put it to the node custom config file named `node-config.7c8cef2b` in Spacemesh app directory.
