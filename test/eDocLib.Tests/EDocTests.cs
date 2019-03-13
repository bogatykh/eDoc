using System.IO;
using System.IO.Compression;
using System.Text;
using Xunit;

namespace eDocLib
{
    public class EdocTests
    {
        [Fact]
        public void CreateWithDataFileTest()
        {
            var target = new Edoc();

            using (var simpleFileStream = new MemoryStream(Encoding.ASCII.GetBytes("simple content")))
            {
                target.AddDataFile(simpleFileStream, "data.txt", "text/plain");

                using (var outputStream = new MemoryStream())
                {
                    target.Save(outputStream);

                    using (ZipArchive archive = new ZipArchive(outputStream))
                    {
                        Assert.Equal(3, archive.Entries.Count);

                        Assert.Equal("mimetype", archive.Entries[0].FullName);
                        Assert.Equal("META-INF/manifest.xml", archive.Entries[1].FullName);
                        Assert.Equal("data.txt", archive.Entries[2].FullName);
                    }
                }
            }
        }

        [Fact]
        public void ReadWithDataFileTest()
        {
            var target = new Edoc();

            using (var simpleFileStream = new MemoryStream(Encoding.ASCII.GetBytes("simple content")))
            {
                target.AddDataFile(simpleFileStream, "data.txt", "text/plain");

                using (var outputStream = new MemoryStream())
                {
                    target.Save(outputStream);

                    outputStream.Seek(0, SeekOrigin.Begin);

                    var target2 = new Edoc(outputStream);

                    Assert.Single(target2.DataFiles);
                }
            }
        }
    }
}
