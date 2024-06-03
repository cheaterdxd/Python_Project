

/*
This is a UI file (.ui.qml) that is intended to be edited in Qt Design Studio only.
It is supposed to be strictly declarative and only uses a subset of QML. If you edit
this file manually, you might introduce QML code that is not supported by Qt Design Studio.
Check out https://doc.qt.io/qtcreator/creator-quick-ui-forms.html for details on .ui.qml files.
*/
import QtQuick 6.5
import QtQuick.Controls 6.5

Rectangle {
    width: Constants.width
    height: Constants.height

    color: Constants.backgroundColor

    Text {
        text: qsTr("Hello Dashboard")
        anchors.centerIn: parent
        font.family: Constants.font.family
    }

    TextInput {
        id: textInput
        x: 560
        y: 281
        width: 80
        height: 20
        text: qsTr("Text Input")
        font.pixelSize: 12
    }

    TextInput {
        id: textInput1
        x: 560
        y: 334
        width: 80
        height: 20
        text: qsTr("Text Input")
        font.pixelSize: 12
    }

    TextInput {
        id: textInput2
        x: 560
        y: 386
        width: 80
        height: 20
        text: qsTr("Text Input")
        font.pixelSize: 12
    }
}
