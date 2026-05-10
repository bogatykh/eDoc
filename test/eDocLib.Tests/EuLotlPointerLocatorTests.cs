using System.Text;
using eDocLib.Trust.Tsl;
using Xunit;

namespace eDocLib.Tests;

public class EuLotlPointerLocatorTests
{
    private const string MinimalLotl = """
        <?xml version="1.0" encoding="UTF-8"?>
        <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
          <SchemeInformation>
            <OtherTSLPointers>
              <OtherTSLPointer>
                <TSLLocation>https://ignore.example/tsl.xml</TSLLocation>
                <AdditionalInformation>
                  <OtherInformation>
                    <SchemeTerritory>DE</SchemeTerritory>
                  </OtherInformation>
                </AdditionalInformation>
              </OtherTSLPointer>
              <OtherTSLPointer>
                <TSLLocation>https://trustlist.gov.lv/tsl/latvian-tsl.xml</TSLLocation>
                <AdditionalInformation>
                  <OtherInformation>
                    <SchemeTerritory>LV</SchemeTerritory>
                  </OtherInformation>
                </AdditionalInformation>
              </OtherTSLPointer>
            </OtherTSLPointers>
          </SchemeInformation>
        </TrustServiceStatusList>
        """;

    [Fact]
    public void EnumerateNationalPointers_returns_all_rows_in_document_order()
    {
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes(MinimalLotl));
        var rows = EuLotlPointerLocator.EnumerateNationalPointers(ms);
        Assert.Equal(2, rows.Count);
        Assert.Equal("DE", rows[0].SchemeTerritory);
        Assert.Equal("https://ignore.example/tsl.xml", rows[0].TsLocation);
        Assert.Equal("LV", rows[1].SchemeTerritory);
        Assert.Equal("https://trustlist.gov.lv/tsl/latvian-tsl.xml", rows[1].TsLocation);
    }

    [Fact]
    public void TryGetNationalTslUrl_finds_LV_pointer()
    {
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes(MinimalLotl));
        var ok = EuLotlPointerLocator.TryGetNationalTslUrl(ms, "LV", out var url);
        Assert.True(ok);
        Assert.Equal("https://trustlist.gov.lv/tsl/latvian-tsl.xml", url);
    }

    [Fact]
    public void TryGetNationalTslUrl_unknown_territory_returns_false()
    {
        using var ms = new MemoryStream(Encoding.UTF8.GetBytes(MinimalLotl));
        var ok = EuLotlPointerLocator.TryGetNationalTslUrl(ms, "MT", out _);
        Assert.False(ok);
    }
}
