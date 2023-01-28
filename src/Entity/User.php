<?php

namespace App\Entity;

use ApiPlatform\Metadata;
use App\Repository\UserRepository;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use App\State\UserProcessor;
use Symfony\Component\Serializer\Annotation\Groups;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[Metadata\ApiResource(
    operations: [
        new Metadata\Get(
            denormalizationContext: ['groups' => 'user:read'],
            security: "object.getId() == user.getId()",
            securityMessage: "You can't get another user."
        ),
        new Metadata\GetCollection(
            denormalizationContext: ['groups' => 'user:read'],
            security: "is_granted('ROLE_ADMIN')",
            securityMessage: "Only admins can get all users."
        ),
        new Metadata\Post(
            denormalizationContext: ['groups' => 'user:post'],
            security: "is_granted('ROLE_ADMIN')",
            securityMessage: "Only admins can create new user."
        ),
        new Metadata\Put(
            denormalizationContext: ['groups' => 'user:put'],
            security: "is_granted('ROLE_ADMIN') or object.getId() == user.getId()",
            securityMessage: "You can't update another user."
        ),
        new Metadata\Delete(
            security: "is_granted('ROLE_ADMIN') or object.getId() == user.getId()",
            securityMessage: "You can't delete another user."
        )
    ],
    normalizationContext: ['groups' => ['user:read']],
    processor: UserProcessor::class,
)]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    #[Groups(["user:read"])]
    private ?int $id = null;

    #[ORM\Column(length: 180, unique: true)]
    #[Assert\Length([
        "min" => 6,
        "max" => 180,
    ])]
    #[Assert\Email]
    #[Groups(["user:read", "user:post", "user:put"])]
    private ?string $email = null;

    #[ORM\Column]
    #[Groups(["user:read", "user:post"])]
    private array $roles = [];

    #[ORM\Column]
    private ?string $password = null;

    #[Assert\Length([
        "min" => 6,
        "max" => 180,
    ])]
    #[Groups(["user:post", "user:put"])]
    private ?string $plainPassword = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUsername(): string
    {
        return $this->getUserIdentifier();
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): self
    {
        $this->email = $email;

        return $this;
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    public function getRoles(): array
    {
        $roles = $this->roles;

        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    public function setRoles(array $roles): self
    {
        $this->roles = $roles;

        return $this;
    }

    public function setPassword(string $password): self
    {
        $this->password = $password;

        return $this;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function eraseCredentials()
    {
        $this->plainPassword = null;
    }

    public function getPlainPassword(): ?string
    {
        return $this->plainPassword;
    }

    public function setPlainPassword(string $plainPassword): self
    {
        $this->plainPassword = $plainPassword;

        return $this;
    }
}
