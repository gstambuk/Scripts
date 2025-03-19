using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace Benchmark
{
    class Program
    {
        // CPU Benchmark
        static double TestCPU()
        {
            int maxIterations = 10000;
            var start = DateTime.Now;
            double cpuScore;

            // Integer Math Test
            for (int i = 0; i < maxIterations; i++)
            {
                double result = i * 2 + 1 - i;
            }

            TimeSpan intTime = DateTime.Now - start;

            // Floating Point Math Test
            start = DateTime.Now;
            for (int i = 0; i < maxIterations; i++)
            {
                double result = Math.Sqrt(i) * Math.PI;
            }

            TimeSpan floatTime = DateTime.Now - start;

            cpuScore = 1 / (intTime.TotalSeconds + floatTime.TotalSeconds);
            return Math.Round(cpuScore * 5000, 2);
        }

        // Memory Benchmark
        static (double writeScore, double readScore) TestMemory()
        {
            int maxIterations = 10000;
            var array = new int[maxIterations];

            // Memory Write Test
            var start = DateTime.Now;
            for (int i = 0; i < maxIterations; i++)
            {
                array[i] = new Random().Next(10000);
            }

            TimeSpan writeTime = DateTime.Now - start;

            // Memory Read Test
            start = DateTime.Now;
            int sum = 0;
            for (int i = 0; i < maxIterations; i++)
            {
                sum += array[i];
            }

            TimeSpan readTime = DateTime.Now - start;

            double memoryWriteScore = 1 / writeTime.TotalSeconds;
            double memoryReadScore = 1 / readTime.TotalSeconds;

            return (Math.Round(memoryWriteScore * 2500, 2), Math.Round(memoryReadScore * 2500, 2));
        }

        // Disk Benchmark
        static double TestDisk()
        {
            string filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "benchmark_testfile.txt");
            string content = new string('0', 1024 * 1024); // 1 MB data

            // Disk Write Test
            var start = DateTime.Now;
            try
            {
                File.WriteAllText(filePath, content);
            }
            catch
            {
                return 0;
            }

            TimeSpan writeTime = DateTime.Now - start;

            // Disk Read Test
            start = DateTime.Now;
            string data = File.ReadAllText(filePath);
            TimeSpan readTime = DateTime.Now - start;

            // Clean up
            File.Delete(filePath);

            double diskScore = 1 / (writeTime.TotalSeconds + readTime.TotalSeconds);
            return Math.Round(diskScore * 10, 2);
        }

        // Graphics Benchmark (Basic Simulation)
        static double TestGraphics()
        {
            int maxFrames = 1000;
            var start = DateTime.Now;
            for (int i = 0; i < maxFrames; i++)
            {
                // Simulate frame rendering by sleeping for 1 ms
                Thread.Sleep(1);
            }

            TimeSpan renderTime = DateTime.Now - start;
            double graphicsScore = 1 / renderTime.TotalSeconds;
            return Math.Round(graphicsScore * 1000, 2);
        }

        // Main Benchmark Runner
        static void RunBenchmark()
        {
            double cpuScore = TestCPU();
            var (memoryWriteScore, memoryReadScore) = TestMemory();
            double diskScore = TestDisk();
            double graphicsScore = TestGraphics();

            string results = $@"
CPU Score: {cpuScore}
Memory Write Score: {memoryWriteScore}
Memory Read Score: {memoryReadScore}
Disk Score: {diskScore}
Graphics Score: {graphicsScore}
";

            // Display results in a MessageBox
            MessageBox.Show(results, "Benchmark Results", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        static void Main(string[] args)
        {
            // Run the benchmark
            RunBenchmark();
        }
    }
}
