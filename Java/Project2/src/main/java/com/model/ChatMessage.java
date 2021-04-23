package com.model;

public class ChatMessage {
    private String sender;
    private String text;
    private String time;

    public ChatMessage() {}

    public ChatMessage(String text) {
        this.text = text;
    }

    public ChatMessage(String sender, String text) {
        this.sender = sender;
        this.text = text;
    }

    public ChatMessage(String sender, String text, String time) {
        this.sender = sender;
        this.text = text;
        this.time = time;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    @Override
    public String toString() {
        return "ChatMessage{" +
                "sender='" + sender + '\'' +
                ", message='" + text + '\'' +
                ", time='" + time + '\'' +
                '}';
    }
}
