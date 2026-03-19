namespace SyslogCEFAnalyzer.Analysis;

using SyslogCEFAnalyzer.Models;

public interface IAnalysisRule
{
    string Name { get; }
    string Category { get; }
    List<AnalysisFinding> Analyze(List<SyslogMessage> messages);
}
