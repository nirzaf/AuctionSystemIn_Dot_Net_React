import React from "react";
import { useAuth } from "../../../utils/hooks/authHook";
import "./Chat.css";

export const Chat = ({ messages }) => {
  const auth = useAuth();

  return (
    <div className="chat">
      <h3 className="text-center">System messages</h3>
      <div className="chat-history">
        <ul className="mx-auto justify-content-center">
          {messages.map((_, index) => {
            let message = messages[messages.length - 1 - index];
            return message.userId === auth.user.id ? (
              <li key={index} className="yellow-message">
                You've successfully bid {process.env.REACT_APP_CURRENCY_SIGN}
                {message.bidAmount}
              </li>
            ) : (
              <li key={index} className="message">
                {process.env.REACT_APP_CURRENCY_SIGN}
                {message.bidAmount.tofixed}: Competing Bid
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
};
