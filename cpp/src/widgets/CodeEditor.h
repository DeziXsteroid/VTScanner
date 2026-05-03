#pragma once

#include <QEvent>
#include <QPaintEvent>
#include <QPlainTextEdit>
#include <QResizeEvent>
#include <QSyntaxHighlighter>

class QWidget;

class CodeEditor final : public QPlainTextEdit {
    Q_OBJECT

public:
    explicit CodeEditor(QWidget* parent = nullptr);
    int lineNumberAreaWidth() const;
    void setJsonMode(bool enabled);

protected:
    void changeEvent(QEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

public:
    void lineNumberAreaPaintEvent(QPaintEvent* event);

private:
    void updateLineNumberAreaWidth();
    void updateLineNumberArea(const QRect& rect, int dy);
    void highlightCurrentLine();

    QWidget* m_lineNumberArea {nullptr};
    QSyntaxHighlighter* m_highlighter {nullptr};
};
