﻿namespace Application.UnitTests.Admin.Commands
{
    using System.Threading;
    using System.Threading.Tasks;
    using Application.Admin.Commands.CreateAdmin;
    using Common.Exceptions;
    using Common.Interfaces;
    using AuctionSystem.Infrastructure.Identity;
    using Domain.Entities;
    using Microsoft.AspNetCore.Identity;
    using Moq;
    using Setup;
    using Xunit;

    public class CreateAdminCommandTests : CommandTestBase
    {
        private readonly IUserManager userManagerService;
        private readonly Mock<UserManager<AuctionUser>> mockedUserManager;

        private readonly CreateAdminCommandHandler handler;

        public CreateAdminCommandTests()
        {
            this.mockedUserManager = IdentityMocker.GetMockedUserManager();
            this.userManagerService = new UserManagerService(
                this.mockedUserManager.Object,
                IdentityMocker.GetMockedRoleManager().Object,
                this.Context);

            this.handler = new CreateAdminCommandHandler(this.userManagerService);
        }

        [Fact]
        public async Task Handle_GivenValidModel_Should_Not_ThrowException()
        {
            this.mockedUserManager
                .Setup(x => x.AddToRoleAsync(It.IsAny<AuctionUser>(), AppConstants.AdministratorRole))
                .ReturnsAsync(IdentityResult.Success);

            var command = new CreateAdminCommand { Email = "test@test.com", Role = "Administrator" };

            await this.handler.Handle(command, CancellationToken.None);
        }

        [Fact]
        public async Task Handle_GivenInvalidRole_Should_Throw_BadRequestException()
            => await Assert.ThrowsAsync<BadRequestException>(() =>
                this.handler.Handle(new CreateAdminCommand()
                {
                    Email = "some random email", Role = "invalid role"
                }, CancellationToken.None));

        [Fact]
        public async Task Handle_InCaseOfAddUserFailure_Should_Throw_BadRequestException()
        {
            this.mockedUserManager
                .Setup(x => x.AddToRoleAsync(It.IsAny<AuctionUser>(), AppConstants.AdministratorRole))
                .ReturnsAsync(IdentityResult.Failed());

            var command = new CreateAdminCommand { Email = "test@test.com", Role = "Administrator" };

            await Assert.ThrowsAsync<BadRequestException>(() => this.handler.Handle(command, CancellationToken.None));
        }
    }
}
