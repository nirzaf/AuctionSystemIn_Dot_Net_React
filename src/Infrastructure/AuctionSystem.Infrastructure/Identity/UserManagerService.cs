using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Application;
using Application.Common.Interfaces;
using Application.Common.Models;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuctionSystem.Infrastructure.Identity
{
    public class UserManagerService : IUserManager
    {
        private readonly IAuctionSystemDbContext context;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly UserManager<AuctionUser> userManager;

        public UserManagerService(
            UserManager<AuctionUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IAuctionSystemDbContext context)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.context = context;
        }

        public async Task<User> GetUserByIdAsync(string id)
        {
            var result = await context
                .Users
                .Where(u => u.Id == id)
                .SingleOrDefaultAsync();

            if (result == null)
            {
                return null;
            }

            var user = new User
            {
                Id = result.Id,
                Email = result.Email,
                UserName = result.UserName,
                FullName = result.FullName,
                AccessFailedCount = result.AccessFailedCount,
                IsEmailConfirmed = result.EmailConfirmed,
                LockoutEnd = result.LockoutEnd,
                PhoneNumber = result.PhoneNumber,
                PhoneNumberConfirmed = result.PhoneNumberConfirmed,
                TwoFactorEnabled = result.TwoFactorEnabled
            };

            return user;
        }

        public async Task<Result> CreateUserAsync(string email, string password, string fullName)
        {
            var user = new AuctionUser
            {
                UserName = email,
                Email = email,
                FullName = fullName
            };

            var result = await userManager.CreateAsync(user, password);
            return result.ToApplicationResult();
        }

        public async Task<Result> CreateUserAsync(AuctionUser user, string password)
        {
            var result = await userManager.CreateAsync(user, password);
            return result.ToApplicationResult();
        }

        public async Task<(Result Result, string UserId)> SignIn(string email, string password)
        {
            var user = await GetDomainUserByEmailAsync(email);
            if (user == null)
            {
                return (Result.Failure(ExceptionMessages.User.InvalidCredentials), null);
            }

            if (await userManager.IsLockedOutAsync(user))
            {
                return (
                    Result.Failure(
                        ExceptionMessages.User.AccountLockout), null);
            }

            var passwordValid = await userManager.CheckPasswordAsync(user, password);
            if (!passwordValid)
            {
                await userManager.AccessFailedAsync(user);
                return (Result.Failure(ExceptionMessages.User.InvalidCredentials), null);
            }

            if (!await userManager.IsEmailConfirmedAsync(user))
            {
                return (
                    Result.Failure(ExceptionMessages.User.ConfirmAccount,
                        ErrorType.TokenExpired), null);
            }

            return (Result.Success(), user.Id);
        }

        public async Task CreateRoleAsync(IdentityRole role)
        {
            var roleExist = await roleManager.RoleExistsAsync(AppConstants.AdministratorRole);

            if (!roleExist)
            {
                await roleManager.CreateAsync(new IdentityRole(AppConstants.AdministratorRole));
            }
        }

        public async Task AddToRoleAsync(AuctionUser user, string role)
        {
            await userManager.AddToRoleAsync(user, role);
        }

        public async Task<Result> AddToRoleAsync(string email, string role, string currentUserId)
        {
            var user = await GetDomainUserByEmailAsync(email);

            if (user == null)
            {
                return Result.Failure(
                    string.Format(ExceptionMessages.Admin.UserNotAddedSuccessfullyToRole, role));
            }

            // This "admin" has no permission
            var refreshToken =
                await GetLastValidToken(currentUserId, CancellationToken.None);
            if (refreshToken == null)
            {
                return Result.Failure(
                    string.Format(ExceptionMessages.Admin.UserNotAddedSuccessfullyToRole, role),
                    ErrorType.TokenExpired);
            }

            var result = await userManager.AddToRoleAsync(user, role);
            return result.Succeeded
                ? Result.Success()
                : Result.Failure(
                    string.Format(ExceptionMessages.Admin.UserNotAddedSuccessfullyToRole, role));
        }

        public async Task<IList<string>> GetUserRolesAsync(string userId)
        {
            var user = await context
                .Users
                .Where(u => u.Id == userId)
                .SingleOrDefaultAsync();

            var userRoles = await userManager.GetRolesAsync(user);
            return userRoles;
        }

        public async Task<string> GetFirstUserId()
        {
            var user = await context.Users.FirstAsync();
            return user.Id;
        }

        public async Task<IEnumerable<string>> GetUsersInRoleAsync(string role)
        {
            var users = await userManager.GetUsersInRoleAsync(role);
            return users.Select(r => r.Id).ToList();
        }

        public async Task<Result> RemoveFromRoleAsync(
            string email,
            string role,
            string currentUserId,
            CancellationToken cancellationToken)
        {
            var user = await GetDomainUserByEmailAsync(email);
            if (user == null)
            {
                return Result.Failure(ExceptionMessages.User.UserNotFound);
            }

            var administrators = await GetUsersInRoleAsync(role);
            var enumerable = administrators as string[] ?? administrators.ToArray();
            if (enumerable.Contains(user.Id) && currentUserId == user.Id)
            {
                return Result.Failure(string.Format(ExceptionMessages.Admin.CannotRemoveSelfFromRole, role));
            }

            if (!enumerable.Contains(user.Id))
            {
                return Result.Failure(string.Format(ExceptionMessages.Admin.NotInRole, user.Email, role));
            }

            var refreshToken =
                await GetLastValidToken(currentUserId, cancellationToken);
            // This "admin" has no permission
            if (refreshToken == null)
            {
                return Result.Failure(string.Format(ExceptionMessages.Admin.UserNotRemovedSuccessfullyFromRole, role),
                    ErrorType.TokenExpired);
            }

            var result = await userManager.RemoveFromRoleAsync(user, role);
            if (!result.Succeeded)
            {
                return Result.Failure(string.Format(ExceptionMessages.Admin.UserNotRemovedSuccessfullyFromRole, role));
            }

            // Invalidate demoted user refresh token
            var removedUserRefreshToken =
                await GetLastValidToken(user.Id, cancellationToken);
            if (removedUserRefreshToken != null)
            {
                removedUserRefreshToken.Invalidated = true;
            }

            await context.SaveChangesAsync(cancellationToken);
            return Result.Success();
        }

        public async Task<string> GenerateEmailConfirmationCode(string email)
        {
            var user = await GetDomainUserByEmailAsync(email);
            if (user == null)
            {
                return null;
            }

            var token = await userManager.GenerateUserTokenAsync(user, FourDigitTokenProvider.FourDigitEmail,
                "Confirmation");
            return token;
        }

        public async Task<bool> ConfirmEmail(string email,
            string token)
        {
            var user = await GetDomainUserByEmailAsync(email);
            if (user == null)
            {
                return false;
            }

            var result = await userManager.VerifyUserTokenAsync(user, FourDigitTokenProvider.FourDigitEmail,
                "Confirmation", token);
            user.EmailConfirmed = true;
            context.Users.Update(user);
            await context.SaveChangesAsync(CancellationToken.None);
            return result;
        }

        private async Task<AuctionUser> GetDomainUserByEmailAsync(string email)
        {
            return await context.Users.Where(u => u.Email == email).SingleOrDefaultAsync();
        }

        private async Task<RefreshToken> GetLastValidToken(string currentUserId, CancellationToken cancellationToken)
        {
            return await context.RefreshTokens.SingleOrDefaultAsync(
                x => x.UserId == currentUserId && !x.Invalidated,
                cancellationToken);
        }
    }
}