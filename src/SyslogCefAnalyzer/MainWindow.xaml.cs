namespace SyslogCEFAnalyzer;

using System.Windows;
using System.Windows.Input;
using SyslogCEFAnalyzer.Models;
using SyslogCEFAnalyzer.ViewModels;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Drop += OnFileDrop;
        DragOver += OnDragOver;
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            var files = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (files?.Length == 1)
            {
                e.Effects = DragDropEffects.Copy;
                e.Handled = true;
                return;
            }
        }
        e.Effects = DragDropEffects.None;
        e.Handled = true;
    }

    private void OnFileDrop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        var files = (string[])e.Data.GetData(DataFormats.FileDrop);
        if (files?.Length != 1) return;

        if (DataContext is MainViewModel vm)
            _ = vm.LoadAndAnalyzeAsync(files[0]);
    }

    private void CopyFilter_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement el && el.Tag is string filter)
        {
            Clipboard.SetText(filter);
            if (DataContext is MainViewModel vm)
                vm.StatusMessage = $"Copied to clipboard: {filter}";
            e.Handled = true;
        }
    }

    /// <summary>Click on a finding to drill down to related messages.</summary>
    private void Finding_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement el && el.DataContext is AnalysisFinding finding)
        {
            if (DataContext is MainViewModel vm)
                vm.ShowRelatedMessagesCommand.Execute(finding);
        }
    }

    /// <summary>Click on a format badge (RFC3164/RFC5424/CEF/Invalid) to filter.</summary>
    private void FormatBadge_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement el && el.Tag is string format)
        {
            if (DataContext is MainViewModel vm)
                vm.FilterByFormatCommand.Execute(format);
        }
    }
}
