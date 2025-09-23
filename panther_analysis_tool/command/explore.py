from panther_analysis_tool.gui.app import PantherAnalysisToolApp


def run() -> tuple[int, str]:
    app = PantherAnalysisToolApp()
    app.run()
    return 0, ""
