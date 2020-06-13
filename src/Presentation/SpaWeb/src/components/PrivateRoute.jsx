import React, { Fragment } from "react";
import { Route } from "react-router-dom";
import { useAuth } from "../utils/hooks/authHook";
import { toast } from "react-toastify";
import { history } from "..";

export const PrivateRoute = ({
  component: Component,
  adminOnly = false,
  ...rest
}) => {
  const { user } = useAuth();

  return (
    <Route
      {...rest}
      render={(props) => {
        if (adminOnly && user.isAdmin) {
          return <Component {...props} />;
        }
        if (adminOnly && !user.isAdmin) {
          history.push("/notFound");
          return;
        }
        if (!adminOnly && user) {
          return <Component {...props} />;
        }
        if (!user) {
          return (
            <Fragment>
              {history.push("/sign-in")}
              {toast.warning("Please sign in!")}
            </Fragment>
          );
        }
      }}
    />
  );
};
